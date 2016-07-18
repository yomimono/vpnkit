module type FLOW_CLIENT = sig
  include Mirage_flow_s.SHUTDOWNABLE

  type address

  val connect: ?read_buffer_size:int -> address
    -> [ `Ok of flow | `Error of [ `Msg of string ] ] Lwt.t
  (** [connect address] creates a connection to [address] and returns
      he connected flow. *)


  val read_into: flow -> Cstruct.t -> [ `Eof | `Error of error | `Ok of unit ] Lwt.t
  (** Completely fills the given buffer with data from [fd] *)
end

module type FLOW_SERVER = sig
  type server
  (* A server bound to some address *)

  type address

  val of_bound_fd: ?read_buffer_size:int -> Unix.file_descr -> server
  (** Create a server from a file descriptor bound to a Unix domain socket
      by some other process and passed to us. *)

  val bind: address -> server Lwt.t
  (** Bind a server to an address *)

  val getsockname: server -> address
  (** Query the address the server is bound to *)

  type flow

  val listen: server -> (flow -> unit Lwt.t) -> unit
  (** Accept connections forever, calling the callback with each one.
      Connections are closed automatically when the callback finishes. *)

  val shutdown: server -> unit Lwt.t
  (** Stop accepting connections on the given server *)
end


module type DATAGRAM = sig

  type address

  type reply = Cstruct.t -> unit Lwt.t

  val input: reply:reply -> src:address -> dst:address -> payload:Cstruct.t -> unit Lwt.t

  module Udp: sig
    type server

    val of_bound_fd: Unix.file_descr -> server

    val bind: address -> server Lwt.t

    val recvfrom: server -> Cstruct.t -> (int * address) Lwt.t

    val sendto: server -> address -> Cstruct.t -> unit Lwt.t

    val shutdown: server -> unit Lwt.t
  end

end


module type SOCKETS = sig
  (* An OS-based BSD sockets implementation *)

  module Datagram: sig

    type address = Ipaddr.t * int

    include DATAGRAM
      with type address := address
  end
  module Stream: sig
    module Tcp: sig
      type address = Ipaddr.V4.t * int

      include FLOW_CLIENT
        with type address := address

      include FLOW_SERVER
        with type address := address
         and type flow := flow
    end

    module Unix: sig
      type address = string

      include FLOW_CLIENT
        with type address := address

      include FLOW_SERVER
        with type address := address
        and type flow := flow

      val unsafe_get_raw_fd: flow -> Unix.file_descr
      (** Return the underlying fd. This is intended for careful integration
          with 3rd party libraries. Don't use this fd at the same time as the
          flow. *)

    end
  end
end

module type FILES = sig
  (** An OS-based file reading implementation *)

  val read_file: string -> [ `Ok of string | `Error of [ `Msg of string ] ] Lwt.t
  (** Read a whole file into a string *)
end

module type HOST = sig
  (** The Host interface *)

  module Sockets: sig
    (** User-space socket connections *)
    include SOCKETS
  end

  module Files: sig
    include FILES
  end

  module Time: V1_LWT.TIME

  module Main: sig
    val run: unit Lwt.t -> unit
    (** Run the main event loop *)

    val run_in_main: (unit -> 'a Lwt.t) -> 'a
    (** Run the function in the main thread *)
  end
end

module type VMNET = sig
  (** A virtual ethernet link to the VM *)

  include V1_LWT.NETWORK

  val add_listener: t -> (Cstruct.t -> unit Lwt.t) -> unit
  (** Add a callback which will be invoked in parallel with all received packets *)

  val after_disconnect: t -> unit Lwt.t
  (** Waits until the network has disconnected *)

  type fd

  val of_fd: client_macaddr:Macaddr.t -> server_macaddr:Macaddr.t
    -> fd -> [ `Ok of t | `Error of [ `Msg of string]] Lwt.t

  val start_capture: t -> ?size_limit:int64 -> string -> unit Lwt.t

  val stop_capture: t -> unit Lwt.t
end

module type TCPIP = sig
  (** A TCP/IP stack *)

  module ICMPV4 : V1_LWT.ICMPV4
    with type ipaddr = Ipaddr.V4.t
     and type 'a io  = 'a Lwt.t

  include V1_LWT.STACKV4
    with type IPV4.prefix = Ipaddr.V4.t
     and type IPV4.uipaddr = Ipaddr.t

  module TCPV4_half_close : Mirage_flow_s.SHUTDOWNABLE
    with type flow = TCPV4.flow
end

module type RESOLV_CONF = sig
  (** The system DNS configuration *)

  val get : unit -> (Ipaddr.t * int) list Lwt.t
end


module type Connector = sig
  (** Make connections into the VM *)

  include FLOW_CLIENT

  val connect: unit -> flow Lwt.t
  (** Connect to the port multiplexing service in the VM *)
end
