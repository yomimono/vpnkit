open Lwt

let src =
  let src = Logs.Src.create "usernet" ~doc:"Mirage TCP/IP <-> socket proxy" in
  Logs.Src.set_level src (Some Logs.Debug);
  src

module Log = (val Logs.src_log src : Logs.LOG)

let client_macaddr = Macaddr.of_string_exn "C0:FF:EE:C0:FF:EE"
(* random MAC from https://www.hellion.org.uk/cgi-bin/randmac.pl *)
let server_macaddr = Macaddr.of_string_exn "F6:16:36:BC:F9:C6"

let mtu = 1452 (* packets above this size with DNF set will get ICMP errors *)

let finally f g =
  Lwt.catch (fun () -> f () >>= fun r -> g () >>= fun () -> return r) (fun e -> g () >>= fun () -> fail e)

let log_exception_continue description f =
  Lwt.catch
    (fun () -> f ())
    (fun e ->
       Log.err (fun f -> f "%s: caught %s" description (Printexc.to_string e));
       Lwt.return ()
    )

let restart_on_change name to_string values =
  Active_config.tl values
  >>= fun values ->
  let v = Active_config.hd values in
  Log.info (fun f -> f "%s changed to %s in the database: restarting" name (to_string v));
  exit 1

type pcap = (string * int64 option) option

let print_pcap = function
  | None -> "disabled"
  | Some (file, None) -> "capturing to " ^ file ^ " with no limit"
  | Some (file, Some limit) -> "capturing to " ^ file ^ " but limited to " ^ (Int64.to_string limit)

type transport = | Tcp of (Tcp.Tcp_packet.t * Cstruct.t)
                 | Udp of (Udp_packet.t * Cstruct.t)
                 | Icmp of (Icmpv4_packet.t * Cstruct.t)

type network = | Ipv4 of (Ipv4_packet.t * Cstruct.t)
               | Ipv6 of (Cstruct.t * Cstruct.t)
               | Arp of Arpv4_packet.t

type decomposed =
  { ethernet : Ethif_packet.t * Cstruct.t;
    network : network;
    transport : transport option;
  }

let decompose buf =
  let open Rresult in
  let get_transport proto buf =
    match Ipv4_packet.Unmarshal.int_to_protocol proto with
    | None -> Result.Ok None
    | Some `ICMP ->
      Icmpv4_packet.Unmarshal.of_cstruct buf >>= fun icmp -> Result.Ok (Some (Icmp icmp))
    | Some `TCP ->
      Tcp.Tcp_packet.Unmarshal.of_cstruct buf >>= fun tcp -> Result.Ok (Some (Tcp tcp))
    | Some `UDP ->
      Udp_packet.Unmarshal.of_cstruct buf >>= fun udp -> Result.Ok (Some (Udp udp))
  in
  let open Ethif_packet in
  Unmarshal.of_cstruct buf >>= fun (e, e_payload) ->
  match e.ethertype with
  | Ethif_wire.IPv6 ->
    let header = Cstruct.sub e_payload 0 Ipv6_wire.sizeof_ipv6 in
    let payload = Cstruct.shift e_payload Ipv6_wire.sizeof_ipv6 in
    get_transport (Ipv6_wire.get_ipv6_nhdr header) payload >>= fun transport ->
    Ok { ethernet = (e, e_payload) ; network = Ipv6 (header, payload);
         transport}
  | Ethif_wire.IPv4 ->
    let open Ipv4_packet in
    Unmarshal.of_cstruct e_payload >>= fun (ip, ip_payload) ->
    get_transport ip.proto ip_payload >>= fun transport ->
    Ok { ethernet = (e, e_payload); network = Ipv4 (ip, ip_payload); transport }
  | Ethif_wire.ARP ->
    match Arpv4_packet.Unmarshal.of_cstruct e_payload with
    | Result.Error e -> Result.Error (Arpv4_packet.Unmarshal.string_of_error e)
    | Result.Ok a ->
      Ok { ethernet = (e, e_payload); network = (Arp a); transport = None; }

let masquerade_dns from_us (ipv4_header : Ipv4_packet.t) (tcp_header : Tcp.Tcp_packet.t) =
  let open Tcp.Tcp_packet in
  match (from_us, tcp_header.src_port) with
  | true, 53 -> begin
    (* TCP on port 53 means we should take some DNS-related action. *)
    (* first, re-read our DNS sources (usually /etc/resolv.conf) *)
    Dns_resolver_unix.create () >>= function
      | { Dns_resolver_unix.servers = (Ipaddr.V4 ip, port) :: _; _ } -> Lwt.return (ip, port)
      | _ -> Log.err (fun f -> f "Failed to discover DNS server: assuming 127.0.0.1/53");
                       Lwt.return (Ipaddr.V4.localhost, 53)
  end
  | true, p -> Lwt.return (Ipaddr.V4.localhost, tcp_header.src_port)
  | false, _ -> Lwt.return Ipv4_packet.(ipv4_header.src, tcp_header.src_port)

module Make(Vmnet: Sig.VMNET)(Resolv_conv: Sig.RESOLV_CONF) = struct
  module Tcpip_stack = Tcpip_stack.Make(Vmnet)
  module Dns_forward = Dns_forward.Make(Tcpip_stack.IPV4)(Tcpip_stack.UDPV4)(Resolv_conv)

  let connect x peer_ip local_ip =
    let config = Tcpip_stack.make ~client_macaddr ~server_macaddr ~peer_ip ~local_ip in
    begin Tcpip_stack.connect ~config x
      >>= function
      | `Error (`Msg m) -> failwith m
      | `Ok s ->
        let (arp, ip, icmp, udp, tcp) = Tcpip_stack.(arpv4 s, ipv4 s, icmpv4 s, udpv4 s, tcpv4 s) in
        Vmnet.add_listener x (fun buf ->
            match decompose buf with
            | Result.Error s -> Log.debug
                                (fun f -> f
                                 "could not parse a packet from vmnet listener (%s), dropping it: %a"
                                s Cstruct.hexdump_pp buf);
              Lwt.return_unit
            | Result.Ok {ethernet; network; transport} ->
            match network, transport with
            | Ipv6 _, _ -> (* TODO: we could attempt to do something brighter here *)
              Log.debug (fun f -> f "Dropping ipv6 packet"); Lwt.return_unit
            | Arp a, _  -> (* ARP packets are either for us or shouldn't be
                              forwarded, so send them to our processor for
                              further consideration *)
              Tcpip_stack.ARPV4.input arp (snd ethernet)
            | Ipv4 (ipv4_header, ipv4_payload), Some (Udp (udp_header, udp_payload)) -> (
              let open Udp_packet in
              let open Ipv4_packet in
              let for_us = Ipaddr.V4.compare ipv4_header.dst local_ip == 0 in
              (* most UDP packets will get forwarded to the socket stack,
                 but there are exceptions for those which have our local_ip
                 set as the destination.  Currently we handle ports 53 and 123
                 ourselves. *)
              let pp_details fmt (ipv4_header, udp_header) =
                Format.fprintf fmt "UDP %a:%d -> %a -> %d"
                  Ipaddr.V4.pp_hum ipv4_header.src udp_header.src_port
                  Ipaddr.V4.pp_hum ipv4_header.dst udp_header.dst_port
              in
              match for_us, udp_header.dst_port with
              | true, 53 ->
                (* DNS packets bound for us should be relayed to our special proxy,
                   which will either answer them directly or send them to our nameservers *)
                Log.debug (fun f -> f "answering DNS query: %a len %d"
                              pp_details (ipv4_header, udp_header)
                              (Cstruct.len (snd ethernet)));
                Dns_forward.input ~ip ~udp ~src:ipv4_header.src
                  ~dst:ipv4_header.dst ~src_port:udp_header.src_port buf
              | true, 123 ->
                (* NTP packets bound for us should be rewritten as queries to localhost,
                   and sent out the socket stack. *)
                Log.debug (fun f -> f "forwarding NTP query to localhost: %a len %d"
				pp_details (ipv4_header, udp_header) (Cstruct.len (snd ethernet)));
                let reply buf = Tcpip_stack.UDPV4.writev ~src:local_ip
                    ~src_port:udp_header.dst_port ~dst:ipv4_header.src
                    ~dst_port:udp_header.src_port udp [ buf ] in
		let localhost = Ipaddr.V4.localhost in
                Socket.Datagram.input ~reply ~src:(localhost, udp_header.src_port)
                  ~dst:(localhost, udp_header.dst_port) ~payload:udp_payload
              | true, _ ->
                Log.debug (fun f -> f "UDP packet for us on a port where we're not listening: %a len %d"
                              pp_details (ipv4_header, udp_header) (Cstruct.len (snd ethernet)));
                (* TODO: send an ICMP message to indicate the port's closed *)
                Lwt.return_unit
              | false, _ ->
                (* send this UDP packet to the socket stack for relay to the broader world *)
                let reply buf = Tcpip_stack.UDPV4.writev ~src:local_ip
                    ~src_port:udp_header.dst_port ~dst:ipv4_header.src
                    ~dst_port:udp_header.src_port udp [ buf ] in
                Socket.Datagram.input ~reply ~src:(ipv4_header.src, udp_header.src_port)
                  ~dst:(ipv4_header.dst, udp_header.dst_port) ~payload:udp_payload
            )
            | Ipv4 (ipv4_header, ipv4_payload), Some (Tcp ((tcp_header : Tcp.Tcp_packet.t), tcp_payload)) ->
                let open Ipv4_packet in
                let open Tcp.Tcp_packet in
                let from_us = Ipaddr.V4.compare ipv4_header.src local_ip == 0 in
                let pp_details fmt (ipv4_header, tcp_header) =
                  Format.fprintf fmt "TCP %a:%d -> %a -> %d"
                  Ipaddr.V4.pp_hum ipv4_header.src tcp_header.src_port
                  Ipaddr.V4.pp_hum ipv4_header.dst tcp_header.dst_port
                in
                masquerade_dns from_us ipv4_header tcp_header >>= fun (ip, port) ->
                Socket.Stream.connect_v4 ip port >>= function
                | `Error (`Msg m) ->
                   Log.info (fun f -> f "%a/%d rejected: %s" Ipaddr.V4.pp_hum ip port m);
                   Lwt.return_unit
                   (* TODO: send rejection message *)
                | `Ok remote ->
                   Lwt.return (fun local ->
                   (* let's do some proxying! *) 
                   finally (fun () ->
                     (* proxy between local and remote *)
                     Log.debug (fun f -> f "%a connected" pp_details (ipv4_header, tcp_header));
                     (* So we need something that represents the local end.  Since we're basically implementing NAT, this is our pull into the hashtable or whatever exists for this module. *)
(* In current master, we return something that accepts (`Accept (fun local -> blah )), so it's not our problem -- we hand it off to someone else. *)
(* but we've altered the control flow here, so now we're somehow not passing this value to something that wants to feed it a local flow; instead we're passing it to something (that something being add_listener_ that expects to take some infrmation and finish with unit. *)
(* this is because on_flow_arrival took an `Accept or `Reject and a flow -> unit, I assume? *)
(* yes, that's it.  input_flow's on_flow_arrival gets plumbed through the rest of pcb.ml .  We want to remove this requirement, since we should be able to state the logic ourselves (or at least do our own tcp implementation which doesn't need a fork!) *)
(* so we need an initialization on this flow.   we should only reach this code path if the thing is new, so we only need to worry about the initial thing.  what's the normal connection establishment API for FLOW?  oh hm, it's not expressed in V1.FLOW; we must get it from the type equivalence in TCP where we know that TCP.t is flow.*)
(* can we just call `input` with a listeners function that always returns `some fun local -> blah`? *)
                     Mirage_flow.proxy (module Clock) (module Tcpip_stack.TCPV4_half_close) local (module Socket.Stream) remote ()
                     >>= function
                     | `Error (`Msg m) ->
Log.err (fun f -> f "%a proxy failed with %s" pp_details (ipv4_header, tcp_header) m);
                       Lwt.return_unit
                     | `Ok (l_stats, r_stats) ->
                       Log.debug (fun f ->
                           f "%a closing: l2r = %s; r2l = %s" pp_details (ipv4_header, tcp_header)
                             (Mirage_flow.CopyStats.to_string l_stats) (Mirage_flow.CopyStats.to_string r_stats)
                         );
                       Lwt.return_unit
                   ) (fun () ->
                     Socket.Stream.close remote
                     >>= fun () ->
                     Log.debug (fun f -> f "%a Socket.Stream.close" pp_details (ipv4_header, tcp_header));
                       Lwt.return_unit
		     )
		   )
	);
        Lwt.return ()
    end

  type config = {
    peer_ip: Ipaddr.V4.t;
    local_ip: Ipaddr.V4.t;
    pcap_settings: pcap Active_config.values;
  }

  let create config =
    let driver = [ "com.docker.driver.amd64-linux" ] in

    let pcap_path = driver @ [ "slirp"; "capture" ] in
    Config.string_option config pcap_path
    >>= fun string_pcap_settings ->
    let parse_pcap = function
      | None -> Lwt.return None
      | Some x ->
        begin match Stringext.split (String.trim x) ~on:':' with
          | [ filename ] ->
            (* Assume 10MiB limit for safety *)
            Lwt.return (Some (filename, Some 16777216L))
          | [ filename; limit ] ->
            let limit =
              try
                Int64.of_string limit
              with
              | _ -> 16777216L in
            let limit = if limit = 0L then None else Some limit in
            Lwt.return (Some (filename, limit))
          | _ ->
            Lwt.return None
        end in
    Active_config.map parse_pcap string_pcap_settings
    >>= fun pcap_settings ->

    let bind_path = driver @ [ "allowed-bind-address" ] in
    Config.string_option config bind_path
    >>= fun string_allowed_bind_address ->
    let parse_bind_address = function
      | None -> Lwt.return None
      | Some x ->
        let strings = List.map String.trim @@ Stringext.split x ~on:',' in
        let ip_opts = List.map
            (fun x ->
               try
                 Some (Ipaddr.of_string_exn x)
               with _ ->
                 Log.err (fun f -> f "Failed to parse IP address in allowed-bind-address: %s" x);
                 None
            ) strings in
        let ips = List.fold_left (fun acc x -> match x with None -> acc | Some x -> x :: acc) [] ip_opts in
        Lwt.return (Some ips) in
    Active_config.map parse_bind_address string_allowed_bind_address
    >>= fun allowed_bind_address ->

    let rec monitor_allowed_bind_settings allowed_bind_address =
      Forward.set_allowed_addresses (Active_config.hd allowed_bind_address);
      Active_config.tl allowed_bind_address
      >>= fun allowed_bind_address ->
      monitor_allowed_bind_settings allowed_bind_address in
    Lwt.async (fun () -> log_exception_continue "monitor_allowed_bind_settings" (fun () -> monitor_allowed_bind_settings allowed_bind_address));

    let peer_ips_path = driver @ [ "slirp"; "docker" ] in
    let parse_ipv4 default x = match Ipaddr.V4.of_string @@ String.trim x with
      | None ->
        Log.err (fun f -> f "Failed to parse IPv4 address '%s', using default of %s" x (Ipaddr.V4.to_string default));
        Lwt.return default
      | Some x -> Lwt.return x in
    let default_peer = "192.168.65.2" in
    let default_host = "192.168.65.1" in
    Config.string config ~default:default_peer peer_ips_path
    >>= fun string_peer_ips ->
    Active_config.map (parse_ipv4 (Ipaddr.V4.of_string_exn default_peer)) string_peer_ips
    >>= fun peer_ips ->
    Lwt.async (fun () -> restart_on_change "slirp/docker" Ipaddr.V4.to_string peer_ips);

    let host_ips_path = driver @ [ "slirp"; "host" ] in
    Config.string config ~default:default_host host_ips_path
    >>= fun string_host_ips ->
    Active_config.map (parse_ipv4 (Ipaddr.V4.of_string_exn default_host)) string_host_ips
    >>= fun host_ips ->
    Lwt.async (fun () -> restart_on_change "slirp/host" Ipaddr.V4.to_string host_ips);

    let peer_ip = Active_config.hd peer_ips in
    let local_ip = Active_config.hd host_ips in

    Log.info (fun f -> f "Creating slirp server pcap_settings:%s peer_ip:%s local_ip:%s"
                 (print_pcap @@ Active_config.hd pcap_settings) (Ipaddr.V4.to_string peer_ip) (Ipaddr.V4.to_string local_ip)
             );
    let t = {
      peer_ip;
      local_ip;
      pcap_settings;
    } in
    Lwt.async (fun () -> Dns_forward.start_reaper ());
    Lwt.return t

  let connect t client =
    Vmnet.of_fd ~client_macaddr ~server_macaddr client
    >>= function
    | `Error (`Msg m) -> failwith m
    | `Ok x ->
      Log.debug (fun f -> f "accepted vmnet connection");

      let rec monitor_pcap_settings pcap_settings =
        ( match Active_config.hd pcap_settings with
          | None ->
            Log.debug (fun f -> f "Disabling any active packet capture");
            Vmnet.stop_capture x
          | Some (filename, size_limit) ->
            Log.debug (fun f -> f "Capturing packets to %s %s" filename (match size_limit with None -> "with no limit" | Some x -> Printf.sprintf "limited to %Ld bytes" x));
            Vmnet.start_capture x ?size_limit filename )
        >>= fun () ->
        Active_config.tl pcap_settings
        >>= fun pcap_settings ->
        monitor_pcap_settings pcap_settings in
      Lwt.async (fun () ->
          log_exception_continue "monitor_pcap_settings"
            (fun () ->
               monitor_pcap_settings t.pcap_settings
            )
        );
      connect x t.peer_ip t.local_ip
end
