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

<<<<<<< HEAD
module Make(Config: Active_config.S)(Vmnet: Sig.VMNET)(Resolv_conf: Sig.RESOLV_CONF)(Host: Sig.HOST) = struct
  module Tcpip_stack = Tcpip_stack.Make(Vmnet)(Host.Time)
  module Dns_forward = Dns_forward.Make(Tcpip_stack.IPV4)(Tcpip_stack.UDPV4)(Resolv_conf)(Host.Sockets)(Host.Time)

module Socket = Host.Sockets

type stack = {
  after_disconnect: unit Lwt.t;
}

let after_disconnect t = t.after_disconnect

let connect x peer_ip local_ip =
  let config = Tcpip_stack.make ~client_macaddr ~server_macaddr ~peer_ip ~local_ip in
        begin Tcpip_stack.connect ~config x
        >>= function
        | `Error (`Msg m) -> failwith m
        | `Ok s ->
          let (ip, udp) = Tcpip_stack.ipv4 s, Tcpip_stack.udpv4 s in
            Tcpip_stack.listen_udpv4 s ~port:53 (Dns_forward.input ~ip ~udp);
            Vmnet.add_listener x (
              fun buf ->
                match (Wire_structs.parse_ethernet_frame buf) with
                | Some (Some Wire_structs.IPv4, _, payload) ->
                  let src = Ipaddr.V4.of_int32 @@ Wire_structs.Ipv4_wire.get_ipv4_src payload in
                  let dst = Ipaddr.V4.of_int32 @@ Wire_structs.Ipv4_wire.get_ipv4_dst payload in
                  begin match Wire_structs.Ipv4_wire.(int_to_protocol @@ get_ipv4_proto payload) with
                    | Some `UDP ->
                      let hlen_version = Wire_structs.Ipv4_wire.get_ipv4_hlen_version payload in
                      let ihl = hlen_version land 0xf in
                      let udp = Cstruct.shift payload (ihl * 4) in
                      let src_port = Wire_structs.get_udp_source_port udp in
                      let dst_port = Wire_structs.get_udp_dest_port udp in
                      let length = Wire_structs.get_udp_length udp in
                      let flags_fragment_offset = Wire_structs.Ipv4_wire.get_ipv4_off payload in
                      let dnf = ((flags_fragment_offset lsr 8) land 0x40) <> 0 in
                      if Cstruct.len udp < length then begin
                        Log.err (fun f -> f "Dropping UDP %s:%d -> %s:%d reported len %d actual len %d"
                                     (Ipaddr.V4.to_string src) src_port
                                     (Ipaddr.V4.to_string dst) dst_port
                                     length (Cstruct.len udp));
                        Lwt.return_unit
                      end else if dnf && (Cstruct.len payload > mtu) then begin
                        let would_fragment ~ip_header ~ip_payload =
                          let open Wire_structs.Ipv4_wire in
                          let header = Cstruct.create sizeof_icmpv4 in
                          set_icmpv4_ty header 0x03;
                          set_icmpv4_code header 0x04;
                          set_icmpv4_csum header 0x0000;
                          (* this field is unused for icmp destination unreachable *)
                          set_icmpv4_id header 0x00;
                          set_icmpv4_seq header mtu;
                          let icmp_payload = match ip_payload with
                            | Some ip_payload ->
                              if (Cstruct.len ip_payload > 8) then begin
                                let ip_payload = Cstruct.sub ip_payload 0 8 in
                                Cstruct.append ip_header ip_payload
                              end else Cstruct.append ip_header ip_payload
                            | None -> ip_header
                          in
                          set_icmpv4_csum header
                            (Tcpip_checksum.ones_complement_list [ header;
                                                                   icmp_payload ]);
                          let icmp_packet = Cstruct.append header icmp_payload in
                          icmp_packet
                        in
                        let ethernet_frame, len = Tcpip_stack.IPV4.allocate (Tcpip_stack.ipv4 s)
                          ~src:dst ~dst:src ~proto:`ICMP in
                        let ethernet_ip_hdr = Cstruct.sub ethernet_frame 0 len in

                        let reply = would_fragment
                            ~ip_header:(Cstruct.sub payload 0 (ihl * 4))
                            ~ip_payload:(Some (Cstruct.sub payload (ihl * 4) 8)) in
                        (* Rather than silently unset the do not fragment bit, we
                           respond with an ICMP error message which will
                           hopefully prompt the other side to send messages we
                           can forward *)
                        Log.err (fun f -> f
                                    "Sending icmp-dst-unreachable in response to UDP %s:%d -> %s:%d with DNF set IPv4 len %d"
                                     (Ipaddr.V4.to_string src) src_port
                                     (Ipaddr.V4.to_string dst) dst_port
                                     length);
                        Tcpip_stack.IPV4.writev (Tcpip_stack.ipv4 s) ethernet_ip_hdr [ reply ];
                      end else begin
                        let payload = Cstruct.sub udp Wire_structs.sizeof_udp (length - Wire_structs.sizeof_udp) in
                        let for_us = Ipaddr.V4.compare dst local_ip == 0 in
                        (* We handle DNS on port 53 ourselves, see [listen_udpv4] above *)
                        (* ... but if it's going to an external IP then we treat it like all other
                           UDP and NAT it *)
                        if (not for_us) then begin
                          Log.debug (fun f -> f "UDP %s:%d -> %s:%d len %d"
                                       (Ipaddr.V4.to_string src) src_port
                                       (Ipaddr.V4.to_string dst) dst_port
                                       length
                                   );
                          let reply buf = Tcpip_stack.UDPV4.writev ~source_ip:dst ~source_port:dst_port ~dest_ip:src ~dest_port:src_port (Tcpip_stack.udpv4 s) [ buf ] in
                          Socket.Datagram.input ~reply ~src:(Ipaddr.V4 src, src_port) ~dst:(Ipaddr.V4 dst, dst_port) ~payload
                        end
                        else if for_us && dst_port == 123 then begin
                          (* port 123 is special -- proxy these requests to
                             our localhost address for the local OSX ntp
                             listener to respond to *)
                          let localhost = Ipaddr.V4.localhost in
                          Log.debug (fun f -> f "UDP/123 request from port %d -- sending it to %a:%d" src_port Ipaddr.V4.pp_hum localhost dst_port);
                          let reply buf = Tcpip_stack.UDPV4.writev ~source_ip:local_ip ~source_port:dst_port ~dest_ip:src ~dest_port:src_port (Tcpip_stack.udpv4 s) [ buf ] in
                          Socket.Datagram.input ~reply ~src:(Ipaddr.V4 src, src_port) ~dst:(Ipaddr.V4 localhost, dst_port) ~payload
                        end else Lwt.return_unit
                      end
                    | _ -> Lwt.return_unit
                  end
                | _ -> Lwt.return_unit
            );
            Tcpip_stack.listen_tcpv4_flow s ~on_flow_arrival:(
              fun ~src:(src_ip, src_port) ~dst:(dst_ip, dst_port) ->

                let for_us src_ip = Ipaddr.V4.compare src_ip local_ip == 0 in
                ( if for_us src_ip && src_port = 53 then begin
                    Resolv_conf.get () (* re-read /etc/resolv.conf *)
                    >>= function
                    | (Ipaddr.V4 ip, port) :: _  -> Lwt.return (ip, port)
                    | _ ->
                      Log.err (fun f -> f "Failed to discover DNS server: assuming 127.0.01");
                      Lwt.return (Ipaddr.V4.of_string_exn "127.0.0.1", 53)
                  end else Lwt.return (src_ip, src_port)
                ) >>= fun (src_ip, src_port) ->
                (* If the traffic is for us, use a local IP address that is really
                   ours, rather than send traffic off to someone else (!) *)
                let src_ip = if for_us src_ip then Ipaddr.V4.localhost else src_ip in
                Socket.Stream.Tcp.connect (src_ip, src_port)
                >>= function
                | `Error (`Msg _) ->
                  return `Reject
                | `Ok remote ->
                  Lwt.return (`Accept (fun local ->
                      finally (fun () ->
                          (* proxy between local and remote *)
                          Mirage_flow.proxy (module Clock) (module Tcpip_stack.TCPV4_half_close) local (module Socket.Stream.Tcp) remote ()
                          >>= function
                          | `Error (`Msg m) ->
                            Log.err (fun f ->
                              let description =
                                Printf.sprintf "TCP %s:%d > %s:%d"
                                  (Ipaddr.V4.to_string src_ip) src_port
                                  (Ipaddr.V4.to_string dst_ip) dst_port in
                               f "%s proxy failed with %s" description m);
                            return ()
                          | `Ok (_l_stats, _r_stats) ->
                            return ()
                        ) (fun () ->
                          Socket.Stream.Tcp.close remote
                          >>= fun () ->
                          Lwt.return ()
                        )
                    ))
            );
            Tcpip_stack.listen s
            >>= fun () ->
            Log.info (fun f -> f "TCP/IP ready");
            Lwt.return { after_disconnect = Vmnet.after_disconnect x }
        end
=======
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
  Ethif_packet.Unmarshal.of_cstruct buf >>= fun (e, e_payload) ->
  match e.ethertype with
  | Ethif_wire.IPv6 ->
    let header = Cstruct.sub e_payload 0 Ipv6_wire.sizeof_ipv6 in
    let payload = Cstruct.shift e_payload Ipv6_wire.sizeof_ipv6 in
    get_transport (Ipv6_wire.get_ipv6_nhdr header) payload >>= fun transport ->
    Ok { ethernet = (e, e_payload) ; network = Ipv6 (header, payload);
         transport}
  | Ethif_wire.IPv4 ->
    Ipv4_packet.Unmarshal.of_cstruct e_payload >>= fun (ip, ip_payload) ->
    get_transport ip.proto ip_payload >>= fun transport ->
    Ok { ethernet = (e, e_payload); network = Ipv4 (ip, ip_payload); transport }
  | Ethif_wire.ARP ->
    match Arpv4_packet.Unmarshal.of_cstruct e_payload with
    | Result.Error e -> Result.Error (Arpv4_packet.Unmarshal.string_of_error e)
    | Result.Ok a ->
      Ok { ethernet = (e, e_payload); network = (Arp a); transport = None; }


module Make(Vmnet: Sig.VMNET)(Resolv_conv: Sig.RESOLV_CONF) = struct
  module Tcpip_stack = Tcpip_stack.Make(Vmnet)
  module Dns_forward = Dns_forward.Make(Tcpip_stack.IPV4)(Tcpip_stack.UDPV4)(Resolv_conv)

  (* we expect this to be listening on the vmnet side. *)
  (* depending on the contents of the message, we'll do one of the following:
     1) do nothing with the message (* NB this is not necessarily drop - another listener may take it *)
        this is the case with all messages that are not IPv4/UDP, so IPv6 or TCP
        messages must be going through a different channel
     2) return an ICMP would-fragment message
     3) construct a corresponding message and send it out the socket stack
        (which may have rewritten headers to make it go to localhost)
     Yeah, OK, so the tcp/udp listeners registered to the stack `s` are also built
     on top of this; whatever doesn't get intercepted by this listen will be sent
     to them.  Ouch.
  *)

  type writeback = Tcpip_stack.buffer -> unit Lwt.t

  type socket_record = {
    src : (Ipaddr.V4.t * int);
    dst : (Ipaddr.V4.t * int);
    payload : Cstruct.t;
  }

  type response = | Ignore of string
                  | Would_fragment of (Ipaddr.V4.t * Cstruct.t) (* dst and icmp packet *)
                  | Socket of (writeback * socket_record)

  let should_forward_from_private local_ip u buf =
    let open Rresult in
    let cant_fragment ethernet_payload =
      let flags_fragment_offset = Ipv4_wire.get_ipv4_off ethernet_payload in
      ((flags_fragment_offset lsr 8) land 0x40) <> 0
    in
    let will_fragment ethernet_payload =
      Cstruct.len ethernet_payload > mtu
    in
    let icmp_unreachable e = cant_fragment e && will_fragment e in
    decompose buf >>= fun {ethernet; network; transport} ->
    match network, transport with
    | Arp _, _ | Ipv6 _, _ -> Result.Ok (Ignore "not ipv4")
    | Ipv4 (ipv4_header, ipv4_payload), Some (Udp (udp_header, udp_payload)) ->
      let for_us = Ipaddr.V4.compare ipv4_header.dst local_ip == 0 in
      if icmp_unreachable (snd ethernet) then begin
        let would_fragment =
          let open Icmpv4_packet in
          { code = Icmpv4_wire.(unreachable_reason_to_int Would_fragment);
            ty   = Icmpv4_wire.Destination_unreachable;
            subheader = Next_hop_mtu mtu }
        in
        Log.err (fun f -> f
                    "Sending icmp-dst-unreachable in response to UDP %a:%d -> %a:%d with DNF set IPv4 len %d"
                    Ipaddr.V4.pp_hum ipv4_header.src udp_header.src_port
                    Ipaddr.V4.pp_hum ipv4_header.dst udp_header.dst_port
                    (Cstruct.len (snd ethernet)));
        Result.Ok (Would_fragment (ipv4_header.src, 
                                   Icmpv4_packet.Marshal.make_cstruct ~payload:ipv4_payload
                                     would_fragment))
        (* TODO: I think this block isn't necessary if we set up the DNS
           listener to restrict traffic to that which is intended for it *)
      end else if (not for_us) then begin
        (* We handle DNS on port 53 ourselves, but if it's going to an external IP
           then we treat it like all other UDP and NAT it *)
        Log.debug (fun f -> f "UDP %a:%d -> %a:%d len %d"
                    Ipaddr.V4.pp_hum ipv4_header.src udp_header.src_port
                    Ipaddr.V4.pp_hum ipv4_header.dst udp_header.dst_port
                    (Cstruct.len (snd ethernet)));
        let reply = fun buf -> Tcpip_stack.UDPV4.writev
            ~source_ip:ipv4_header.dst ~source_port:udp_header.dst_port
            ~dest_ip:ipv4_header.src ~dest_port:udp_header.src_port u [ buf ] in
        let reply_record = {
          src=(ipv4_header.src, udp_header.src_port); dst=(ipv4_header.dst,
                                                           udp_header.dst_port); payload=udp_payload; } in
        Result.Ok (Socket (reply, reply_record))
      end else if for_us && udp_header.dst_port == 123 then begin
        (* port 123 is special -- proxy these requests to our localhost address for the local OSX ntp
           listener to respond to *)
        let localhost = Ipaddr.V4.localhost in
        Log.debug (fun f -> f "UDP/123 request from port %d -- sending it to %a:%d"
                      udp_header.src_port Ipaddr.V4.pp_hum localhost udp_header.dst_port);
        let reply buf = Tcpip_stack.UDPV4.writev ~source_ip:local_ip
            ~source_port:udp_header.dst_port ~dest_ip:ipv4_header.src
            ~dest_port:udp_header.src_port u [ buf ] in
        let reply_record = { src=(localhost, udp_header.src_port);
                             dst=(localhost, udp_header.dst_port); payload = udp_payload}
        in
        Result.Ok (Socket (reply, reply_record))
      end
      else
        (* this particular function doesn't need to do a transformation *)
        Result.Ok (Ignore "ipv4 and udp, but no transformation or further match needed")
    | Ipv4 _, _ -> Result.Ok (Ignore "ipv4, but not udp")

  let connect x peer_ip local_ip =
    let config = Tcpip_stack.make ~client_macaddr ~server_macaddr ~peer_ip ~local_ip in
    begin Tcpip_stack.connect ~config x
      >>= function
      | `Error (`Msg m) -> failwith m
      | `Ok s ->
        let (ip, udp) = Tcpip_stack.ipv4 s, Tcpip_stack.udpv4 s in
        Tcpip_stack.listen_udpv4 s ~port:53 (Dns_forward.input ~ip ~udp);
        Vmnet.add_listener x (fun buf ->
            match should_forward_from_private local_ip udp buf with
            | Result.Error s ->
              Log.debug (fun f -> f "vmnet listener had an error %s parsing packet %a -- the traffic will be dropped"
                            s Cstruct.hexdump_pp buf);
              Lwt.return_unit
            | Result.Ok (Ignore s) ->
              Log.debug (fun f -> f "vmnet listener is not acting on packet because %s" s);
              Lwt.return_unit
            | Result.Ok (Would_fragment (dst, payload)) ->
              let (f, len) = Tcpip_stack.IPV4.allocate ip ~src:local_ip ~dst ~proto:`ICMP in
              Cstruct.blit payload 0 f len (Cstruct.len payload);
              Tcpip_stack.IPV4.writev ip f [Cstruct.shift f len]
            | Result.Ok (Socket (reply, {src; dst; payload})) ->
              Socket.Datagram.input ~reply ~src ~dst ~payload
          );
        Tcpip_stack.listen_tcpv4_flow s ~on_flow_arrival:(
          fun ~src:(src_ip, src_port) ~dst:(dst_ip, dst_port) ->
            let description =
              Printf.sprintf "TCP %s:%d > %s:%d"
                (Ipaddr.V4.to_string src_ip) src_port
                (Ipaddr.V4.to_string dst_ip) dst_port in
            Log.debug (fun f -> f "%s connecting" description);
            let for_us = Ipaddr.V4.compare src_ip local_ip == 0 in
            ( if for_us && src_port = 53 then begin
                  Dns_resolver_unix.create () (* re-read /etc/resolv.conf *)
                  >>= function
                  | { Dns_resolver_unix.servers = (Ipaddr.V4 ip, port) :: _; _ } -> Lwt.return (ip, port)
                  | _ ->
                    Log.err (fun f -> f "Failed to discover DNS server: assuming 127.0.01");
                    Lwt.return (Ipaddr.V4.of_string_exn "127.0.0.1", 53)
                end else Lwt.return (src_ip, src_port)
            ) >>= fun (src_ip, src_port) ->
            (* If the traffic is for us, use a local IP address that is really
               ours, rather than send traffic off to someone else (!) *)
            let src_ip = if for_us then Ipaddr.V4.localhost else src_ip in
            Socket.Stream.connect_v4 src_ip src_port
            >>= function
            | `Error (`Msg m) ->
              Log.info (fun f -> f "%s rejected: %s" description m);
              return `Reject
            | `Ok remote ->
              Lwt.return (`Accept (fun local ->
                  finally (fun () ->
                      (* proxy between local and remote *)
                      Log.debug (fun f -> f "%s connected" description);
                      Mirage_flow.proxy (module Clock) (module Tcpip_stack.TCPV4_half_close) local (module Socket.Stream) remote ()
                      >>= function
                      | `Error (`Msg m) ->
                        Log.err (fun f -> f "%s proxy failed with %s" description m);
                        return ()
                      | `Ok (l_stats, r_stats) ->
                        Log.debug (fun f ->
                            f "%s closing: l2r = %s; r2l = %s" description
                              (Mirage_flow.CopyStats.to_string l_stats) (Mirage_flow.CopyStats.to_string r_stats)
                          );
                        return ()
                    ) (fun () ->
                      Socket.Stream.close remote
                      >>= fun () ->
                      Log.debug (fun f -> f "%s Socket.Stream.close" description);
                      Lwt.return ()
                    )
                ))
        );
        Tcpip_stack.listen s
        >>= fun () ->
        Log.info (fun f -> f "TCP/IP ready");
        Lwt.return ()
    end
>>>>>>> WIP - pull routing logic out of slirp main, use result types rather than

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
