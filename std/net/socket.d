// 
// XXX check all enforce and use errnoEnforce
module std.net.socket; 

import std.conv;
import std.string;
import std.exception;
import std.algorithm;
import std.stdio;
import std.typecons;
import std.typetuple;
import std.container;
import core.stdc.string;
import core.stdc.stdlib;
import core.memory;
import core.time;

import std.functional;

version(Windows)
{
   pragma(lib, "ws2_32.lib");
   //pragma(lib, "wsock32.lib");

   import std.c.windows.windows;
   import std.c.windows.winsock;

   shared static this()
   {
      WSADATA wd;

      auto val = WSAStartup(0x2020, &wd);
      enforce(!val, new Exception("Unable to initialize socket library"));
   }

   shared static ~this()
   {
      WSACleanup();
   }
}
else version(Posix)
{
   import core.sys.posix.sys.socket;
   import core.sys.posix.netdb;
   import core.sys.posix.netinet.in_;
   import core.sys.posix.unistd;
   import core.sys.posix.fcntl;

   version(linux)
   {
      import core.sys.linux.sys.epoll;
   }
}
private enum : uint { TOKEN = 0xACE97531 }

/++
+/
enum Family
{
   unspec = AF_UNSPEC,///
   inet = AF_INET,///
   inet6 = AF_INET6///
}

/++
+/
enum Type
{
   unspec = 0,///
   stream = SOCK_STREAM,///
   dgram = SOCK_DGRAM,///
   raw = SOCK_RAW///
}

/++
+/
enum Protocol
{
   unspec = 0,///
   tcp = IPPROTO_TCP,///
   udp = IPPROTO_UDP///
}

/++
+/
struct Address
{
   unittest
   {
      // basic lookup
      assert(Address.lookup(null, "4747").length > 0);
      assert(Address.lookup("localhost", null).length > 0);
      assert(Address.lookup("localhost", "4747").length > 0);

      // lookup family
      assert(Address.lookup(null, "4747", Family.inet).length > 0);
      assert(Address.lookup(null, "4747", Family.inet6).length > 0);

      // lookup type
      assert(Address.lookup(null,
                            "4747",
                            Family.inet,
                            Type.stream).length > 0);
      assert(Address.lookup(null,
                            "4747",
                            Family.inet6,
                            Type.stream).length > 0);
      assert(Address.lookup(null,
                            "4747",
                            Family.inet,
                            Type.dgram).length > 0);
      assert(Address.lookup(null,
                            "4747",
                            Family.inet6,
                            Type.dgram).length > 0);
      assert(Address.lookup("localhost",
                            null,
                            Family.inet,
                            Type.raw).length > 0);
      assert(Address.lookup("localhost",
                            null,
                            Family.inet6,
                            Type.raw).length > 0);

      // lookup protocol
      assert(Address.lookup(null,
                            "4747",
                            Family.inet,
                            Type.stream,
                            Protocol.tcp).length > 0);
      assert(Address.lookup(null,
                            "4747",
                            Family.inet6,
                            Type.stream,
                            Protocol.tcp).length > 0);
      assert(Address.lookup(null,
                            "4747",
                            Family.inet,
                            Type.dgram,
                            Protocol.udp).length > 0);
      assert(Address.lookup(null,
                            "4747",
                            Family.inet6,
                            Type.dgram,
                            Protocol.udp).length > 0);
   }

   /++
    +/
   static immutable(Address)[] lookup(string nodename,
                                      string service,
                                      Family family = Family.unspec,
                                      Type type = Type.unspec,
                                      Protocol protocol = Protocol.unspec,
                                      int flags = 0)
   {
      string formatParameters()
      {
         return format(`Address.lookup("%s", "%s", %s, %s, %s, %x) error:`,
                       nodename,
                       service,
                       to!string(family),
                       to!string(type),
                       to!string(protocol),
                       flags);
      }

      addrinfo hint;
      hint.ai_family = family;
      hint.ai_socktype = type;
      hint.ai_protocol = protocol;
      hint.ai_flags = flags;

      addrinfo* res;

      auto errorCode = getaddrinfo(nodename == "" ? null : toStringz(nodename),
                                   service == "" ? null : toStringz(service),
                                   &hint,
                                   &res);
      enforce(errorCode == 0,
              new NetworkException(formatParameters(), errorCode));
      scope(exit) freeaddrinfo(res);

      immutable(Address)[] result;
      for(auto current = res; current !is null; current = current.ai_next)
      {
         immutable address = Address(*current);
         result ~= address;
      }

      return result;
   }

   ///
   const @property string nodename()
   {
      char[max(INET_ADDRSTRLEN, INET6_ADDRSTRLEN)] buf;
      string addr;
      void* addrPointer;

      if(family == Family.inet)
      {
         addrPointer = &(cast(sockaddr_in*)&_socketAddress).sin_addr;
      }
      else if(family == Family.inet6)
      {
         addrPointer = &(cast(sockaddr_in6*)&_socketAddress).sin6_addr;
      }

      if(addrPointer &&
         inet_ntop(_address.ai_family, addrPointer, buf.ptr, buf.length))
      {
         addr = to!string(buf.ptr);
      }

      return addr;
   }

   ///
   const @property string service() 
   {
      ushort port;
      if(family == Family.inet)
      {
         port = ntohs((cast(sockaddr_in*)&_socketAddress).sin_port);
      }
      else if(family == Family.inet6)
      {
         port = ntohs((cast(sockaddr_in6*)&_socketAddress).sin6_port);
      }

      return to!string(port);
   }

   ///
   const @property Family family() { return cast(Family)_address.ai_family; }

   ///
   const @property Type type() { return cast(Type)_address.ai_socktype; }

   ///
   const @property Protocol protocol()
   {
      return cast(Protocol)_address.ai_protocol;
   }

   ///
   const string toString()
   {
      return "<Address: " ~ to!string(family) ~ ", " ~ to!string(type) ~
             ", " ~ to!string(protocol) ~ ", " ~ nodename ~ ", " ~
             service ~ ">";
   }

   const bool opEquals(ref const Address rhs)
   {
      return (family == rhs.family && type == rhs.type &&
              protocol == rhs.protocol && sockAddrLen == rhs.sockAddrLen &&
              memcmp(sockAddr, rhs.sockAddr, sockAddrLen)); 
   }

   private this(addrinfo address)
   {
      if(address.ai_addr != null)
         memcpy(&_socketAddress, address.ai_addr, address.ai_addrlen);

      address.ai_canonname = null;
      address.ai_next = null;
      address.ai_addr = null;

      swap(_address, address);
   }

   private this(Family family,
                Type type,
                Protocol protocol,
                sockaddr_storage addr,
                socklen_t addrlen)
   {
      _address.ai_family = family;
      _address.ai_socktype = type;
      _address.ai_protocol = protocol;
      _address.ai_addrlen = addrlen;

      swap(_socketAddress, addr);
   }

   private const @property const(sockaddr)* sockAddr()
   {
      return cast(sockaddr*) &_socketAddress;
   }
   private const @property size_t sockAddrLen()
   {
      return _address.ai_addrlen;
   }
   private void setSockAddr(sockaddr_storage addr, socklen_t length)
   {
      swap(_socketAddress, addr);
      _address.ai_addrlen = length;
   }

   private addrinfo _address;
   private sockaddr_storage _socketAddress;
}

final class NetworkException : Exception
{
   this(string message,
        int errcode,
        string file = __FILE__,
        int line = __LINE__) 
   {
      _errorCode = errcode;
      super(message ~ " (" ~ to!string(gai_strerror(errcode)) ~ ")",
            file,
            line);
   }

   const pure nothrow @property int errorCode() { return _errorCode; }

   private int _errorCode;
}


unittest
{
   Socket* psock;

   {
      auto sock = Socket(Family.inet, Type.stream, Protocol.tcp);
      psock = &sock;

      assert(sock._socket.handle > 0);
      {
         auto sock2 = sock;
         assert(sock2._socket.refCount == 2);

         {
            Socket sock3;
            assert(!sock3.isOpened); 
            sock3 = sock2;
            assert(sock3._socket.refCount == 3);
         }

         assert(sock2._socket.refCount == 2);
      }

      assert(sock._socket.refCount == 1);
   }

   assert(psock._socket is null);
}

/++
+/
struct Socket
{
   unittest
   {
      auto sock = Socket.socket(Family.inet, Type.stream, Protocol.unspec);
      sock.self;
   }
   /++
    +/
   static Socket socket(Family family, Type type, Protocol protocol)
   {
      return Socket(family, type, protocol);
   }

   unittest
   {
      byte[] buffer = ['H', 'e', 'l', 'l', 'o'];

      auto servers = streamServers("0", 1); 
      foreach(server; servers)
      {
         auto address = server.self;
         auto client = streamClient(address.nodename, address.service);
         client.send(buffer);

         auto peer = server.accept();
         peer.receive(buffer);
      }
   }

   /++
    +/
   static Socket[] streamServers(string nodename,
                                 string service,
                                 int backlog,
                                 bool isBlocking = true)
   {
      auto addresses = Address.lookup(nodename,
                                      service,
                                      Family.unspec,
                                      Type.stream,
                                      Protocol.unspec,
                                      AI_PASSIVE);

      auto sockets = new Socket[addresses.length];
      foreach(i, address; addresses)
      {
         auto sock = Socket(address.family, address.type, address.protocol);
         sock.isBlocking = isBlocking;
         sock.bind(address);
         sock.listen(backlog);

         sockets[i] = sock;
      }

      return sockets;
   }
   ///
   static Socket[] streamServers(string service,
                                 int backlog,
                                 bool isBlocking = true)
   {
      return streamServers(null, service, backlog, isBlocking);
   }

   /++
    +/
   static Socket streamClient(string nodename,
                              string service,
                              bool isBlocking = true)
   {
      auto addresses = Address.lookup(nodename,
                                      service,
                                      Family.unspec,
                                      Type.stream);

      Exception exception;
      foreach(address; addresses)
      {
         auto sock = Socket(address.family, address.type, address.protocol);
         sock.isBlocking = isBlocking;
         try sock.connect(address);
         catch(Exception e) exception = e;

         return sock;
      }

      if(exception !is null) throw exception;
      else
      {
         // this should never happend but just in case.
         enforce(false, format(`Socket.createTcpClient("%s", "%s", %s) error.`,
                               nodename,
                               service,
                               isBlocking));
         assert(false);
      }
   }

   unittest
   {
      byte[] buffer = ['H', 'e', 'l', 'l', 'o'];

      auto servers = Socket.dgramServers("0");
      foreach(server; servers)
      {
         auto address = server.self;
         auto client = dgramClient(address.nodename, address.service);
         client.send(buffer);

         auto result = server.receiveFrom(buffer);
      }
   }

   /++
    +/
   static Socket[] dgramServers(string nodename,
                                string service,
                                bool isBlocking = true)
   {
      auto addresses = Address.lookup(nodename,
                                      service,
                                      Family.unspec,
                                      Type.dgram,
                                      Protocol.unspec,
                                      AI_PASSIVE);

      auto sockets = new Socket[addresses.length];
      foreach(i, address; addresses)
      {
         auto sock = Socket(address.family, address.type, address.protocol);
         sock.isBlocking = isBlocking;
         sock.bind(address);

         sockets[i] = sock;
      }

      return sockets;
   }
   ///
   static Socket[] dgramServers(string service, bool isBlocking = true)
   {
      return dgramServers(null, service, isBlocking);
   }

   /++
    +/
   static Socket dgramClient(string nodename,
                             string service,
                             bool isBlocking = true)
   {
      auto addresses = Address.lookup(nodename,
                                      service,
                                      Family.unspec,
                                      Type.dgram);

      Exception exception;
      foreach(address; addresses)
      {
         auto sock = Socket(address.family, address.type, address.protocol);
         sock.isBlocking = isBlocking;
         try sock.connect(address);
         catch(Exception e) exception = e;

         return sock;
      }

      if(exception !is null) throw exception;
      else
      {
         // this should never happend but just in case.
         enforce(false, format(`Socket.createTcpClient("%s", "%s", %s) error.`,
                               nodename,
                               service,
                               isBlocking));
         assert(false);
      }
   }

   this(this) { if(_socket) ++_socket.refCount; }

   ~this()
   {
      if(_token == TOKEN && _socket !is null && --_socket.refCount == 0)
      {
         if(isOpened) close();
         free(_socket);
      }
      _socket = null;
      _token = 0;
   }

   ref Socket opAssign(Socket rhs)
   {
      swap(_socket, rhs._socket);
      swap(_token, rhs._token);
      return this;
   }

   unittest
   {
      Socket socket;
      assert(!socket.isOpened);
      socket = Socket.socket(Family.inet, Type.stream, Protocol.unspec);
      assert(socket.isOpened);
      socket.close();
      assert(!socket.isOpened);
   }

   /++
    +/
   const pure nothrow @property bool isOpened()
   {
      return _socket !is null && _socket.handle > 0;
   }

   unittest
   {
      auto sock = Socket(Family.inet, Type.stream, Protocol.tcp);
      assert(sock.isBlocking == true);
      assert((sock.isBlocking = false) == false) ;
      assert(sock.isBlocking == false);
   }

   /++
    +/
   const @property bool isBlocking()
   {
      // XXX check errorno
      if(!isOpened) return true;

      auto result = fcntl(_socket.handle, F_GETFL);
      enforce(result != -1);
      return !(result & O_NONBLOCK);
   }
   /// ditto
   const @property bool isBlocking(bool blocking)
   {
      enforce(isOpened);
      // XXX check errorno
      auto result = fcntl(_socket.handle, F_GETFL);
      enforce(result != -1);
       
      if (blocking) {
         result &= ~O_NONBLOCK;
      } else {
         result |= O_NONBLOCK;
      }

      enforce(fcntl(_socket.handle, F_SETFL, result) != -1);
      return !(result & O_NONBLOCK);
   }

   /++
    +/
   const @property immutable(Address) self()
   {
      enforce(isOpened);

      sockaddr_storage addr;
      socklen_t len = typeof(addr).sizeof;
      errnoEnforce(getsockname(_socket.handle,
                               cast(sockaddr*)&addr,
                               &len) == 0,
                   "Socket.self error:");

      immutable result = Address(_socket.family,
                                 _socket.type,
                                 _socket.protocol,
                                 addr,
                                 len);
      return result;
   }

   /++
    +/
   const @property immutable(Address) peer()
   {
      enforce(isOpened);

      sockaddr_storage addr;
      socklen_t len = typeof(addr).sizeof;
      errnoEnforce(getpeername(_socket.handle,
                               cast(sockaddr*)&addr,
                               &len) != -1,
                   "Socket.peer error:");

      immutable result = Address(_socket.family,
                                 _socket.type,
                                 _socket.protocol,
                                 addr,
                                 len);
      return result;
   }

   unittest
   {
      // === test success (we can only bind to local addresses) ===
      auto addresses = Address.lookup("localhost",
                                      null,
                                      Family.unspec,
                                      Type.unspec,
                                      Protocol.unspec,
                                      AI_PASSIVE);
      // bind to all of them
      foreach(address; addresses)
      {
         // don't bind to raw sockets because we probably don't have permission
         if(address.type == Type.raw) continue;

         auto socket = Socket(address.family, address.type, address.protocol);
         socket.bind(address);
      }

      // === test failure (we can't bind to remote addresses) ===
      addresses = Address.lookup("111.111.111.111", // XXX check doesn't exist
                                 null,
                                 Family.unspec,
                                 Type.unspec,
                                 Protocol.unspec,
                                 AI_PASSIVE);
      addresses ~= Address.lookup("1::1", // XXX check doesn't exist
                                  null,
                                  Family.unspec,
                                  Type.unspec,
                                  Protocol.unspec,
                                  AI_PASSIVE);

      // bind to all of them
      foreach(address; addresses)
      {
         // don't bind to raw sockets because we probably don't have permission
         if(address.type == Type.raw) continue;

         auto socket = Socket(address.family, address.type, address.protocol);
         assertThrown(socket.bind(address));
      }
   }

   /++
    +/
   const void bind(in Address address)
   {
      enforce(isOpened);
      errnoEnforce(.bind(_socket.handle,
                         address.sockAddr,
                         address.sockAddrLen) == 0,
                   format("Socket.bind(%s) error:", to!string(address)));
   }

   unittest
   {
      // === test connect to streams ===
      auto addresses = Address.lookup("localhost",
                                      null,
                                      Family.unspec,
                                      Type.stream);
      foreach(address; addresses)
      {
         // create the server
         auto socket1 = Socket(address.family, address.type, address.protocol);
         socket1.bind(address);
         socket1.listen(1);

         // try to connect to it
         auto actual = socket1.self;
         auto socket2 = Socket(actual.family, actual.type, actual.protocol);
         socket2.connect(actual);

         // connect to closed server should fail
         socket1.close();
         socket2 = Socket(actual.family, actual.type, actual.protocol);
         assertThrown(socket2.connect(actual));
      }

      // === test connect to dgram ===
      addresses = Address.lookup("localhost",
                                 "4747",
                                 Family.unspec,
                                 Type.dgram);
      foreach(address; addresses)
      {
         // no peer set
         auto socket1 = Socket(address.family, address.type, address.protocol);
         assertThrown(socket1.peer);

         // try to connect to it
         socket1.connect(address);
         socket1.peer; // peer should succeed
      }
   }

   /++
    +/
   const void connect(in Address address)
   {
      enforce(isOpened);
      errnoEnforce(.connect(_socket.handle,
                            address.sockAddr,
                            address.sockAddrLen) == 0,
                   format("Socket.conect(%s) error:", to!string(address)));
   }

   unittest
   {
      // === test listen (we can only listen on streams) ===
      auto addresses = Address.lookup("localhost",
                                      null,
                                      Family.unspec,
                                      Type.stream);
      foreach(address; addresses)
      {
         auto socket = Socket(address.family, address.type, address.protocol);
         socket.listen(1);
      }

      // === test error in listen (we cannot listen to dgram) ===
      addresses = Address.lookup("localhost", null, Family.unspec, Type.dgram);
      foreach(address; addresses)
      {
         auto socket = Socket(address.family, address.type, address.protocol);
         assertThrown(socket.listen(1));
      }
   }

   /++
    +/
   const void listen(uint backlog)
   {
      enforce(isOpened);
      errnoEnforce(.listen(_socket.handle, backlog) == 0,
                   format("Socket.listen(%s) error:", backlog));
   }

   unittest
   {
      // === test accept (we can only accept on streams) ===
      auto addresses = Address.lookup("localhost",
                                      null,
                                      Family.unspec,
                                      Type.stream);
      foreach(address; addresses)
      {
         auto socket1 = Socket(address.family, address.type, address.protocol);
         socket1.bind(address);
         socket1.listen(1);

         auto actual = socket1.self;
         auto socket2 = Socket(actual.family, actual.type, actual.protocol);
         socket2.connect(actual);

         auto socket3 = socket1.accept();
         socket3.self;
      }

      // === test accept error (we cannot accept on dgram) ===
      addresses = Address.lookup("localhost",
                                 null,
                                 Family.unspec,
                                 Type.dgram);
      foreach(address; addresses)
      {
         auto socket1 = Socket(address.family, address.type, address.protocol);
         
         // BUG: http://d.puremagic.com/issues/show_bug.cgi?id=6167
         // assertThrown(socket1.accept());
         auto threw = false;
         try { socket1.accept(); } catch(Exception e) { threw = true; }
         assert(threw);
      }
   }

   /++
    +/
   const Socket accept()
   {
      enforce(isOpened);
      auto result = .accept(_socket.handle, null, null);
      errnoEnforce(result > 0,
                   "Socket.accept() error:");

      return Socket(result, _socket.family, _socket.type, _socket.protocol);
   }

   unittest
   {
      // === test sending stream messages ===
      auto addresses = Address.lookup("localhost",
                                      null,
                                      Family.unspec,
                                      Type.stream,
                                      Protocol.unspec,
                                      AI_PASSIVE);
      foreach(address; addresses)
      {
         byte[] buffer = ['H', 'e', 'l', 'l', 'o'];

         // create server
         auto socket1 = Socket(address.family, address.type, address.protocol);
         socket1.bind(address);
         socket1.listen(1);

         // connect to server
         auto actual = socket1.self;
         auto socket2 = Socket(actual.family, actual.type, actual.protocol);
         socket2.connect(actual);

         auto socket3 = socket1.accept();

         // test sending
         auto remainder = buffer;
         while(remainder.length > 0) remainder = socket2.send(remainder);

         remainder = buffer;
         while(remainder.length > 0) remainder = socket3.send(remainder);
      }

      // === test sending dgram messages ===
      addresses = Address.lookup("localhost",
                                 null,
                                 Family.unspec,
                                 Type.dgram);
      foreach(address; addresses)
      {
         byte[] buffer = ['H', 'e', 'l', 'l', 'o'];
         // create one end
         auto socket1 = Socket(address.family, address.type, address.protocol);
         socket1.bind(address);

         // connect the other end to this end
         auto actual = socket1.self;
         auto socket2 = Socket(actual.family, actual.type, actual.protocol);
         socket2.connect(actual);

         // send using the connect socket
         auto remainder = buffer;
         while(remainder.length > 0) remainder = socket2.send(remainder);

         // send using the unconnected socket
         remainder = buffer;
         while(remainder.length > 0) remainder = socket1.sendTo(remainder,
                                                                socket2.self);

         // can't use send on the unconnted socket
         assertThrown(socket1.send(buffer));
      }
   }

   /++
    +/
   const inout(byte[]) send(inout byte[] buffer, int flags = 0)
   {
      enforce(isOpened);
      enforce(buffer.length > 0);

      auto size = .send(_socket.handle, buffer.ptr, buffer.length, flags);
      errnoEnforce(size != -1,
                   format("Socket.send(byte[%x], %x)", buffer.length, flags));

      return buffer[size .. $];
   }
   ///
   const inout(byte[]) sendTo(inout byte[] buffer,
                              in Address address,
                              int flags = 0)
   {
      enforce(isOpened);
      enforce(buffer.length > 0);

      auto size = sendto(_socket.handle,
                         buffer.ptr,
                         buffer.length,
                         flags,
                         address.sockAddr,
                         address.sockAddrLen);
      errnoEnforce(size != -1,
                   format("Socket.sendTo(byte[%x], %s, %x)",
                          buffer.length,
                          to!string(address),
                          flags));

      return buffer[size .. $];
   }

   unittest
   {
      // === test receiving stream messages ===
      auto addresses = Address.lookup("localhost",
                                      null,
                                      Family.unspec,
                                      Type.stream,
                                      Protocol.unspec,
                                      AI_PASSIVE);
      foreach(address; addresses)
      {
         byte[] buffer = ['H', 'e', 'l', 'l', 'o'];

         // create server
         auto socket1 = Socket(address.family, address.type, address.protocol);
         socket1.bind(address);
         socket1.listen(1);

         // connect to server
         auto actual = socket1.self;
         auto socket2 = Socket(actual.family, actual.type, actual.protocol);
         socket2.connect(actual);

         auto socket3 = socket1.accept();

         // test sending
         auto remainder = buffer;
         while(remainder.length > 0) remainder = socket2.send(remainder);

         remainder = new byte[buffer.length];
         auto bufferView = buffer;
         while(bufferView.length > 0)
         {
            auto received = socket3.receive(remainder);
            assert(received == bufferView[0 .. received.length]);

            // prepare for the next loop
            remainder = remainder[received.length .. $];
            bufferView = bufferView[received.length .. $];
         }
      }

      // === test receiving dgram messages ===
      addresses = Address.lookup("localhost",
                                 null,
                                 Family.unspec,
                                 Type.dgram);
      foreach(address; addresses)
      {
         byte[] buffer = ['H', 'e', 'l', 'l', 'o'];
         // create one end
         auto socket1 = Socket(address.family, address.type, address.protocol);
         socket1.bind(address);

         // connect the other end to this end
         auto actual = socket1.self;
         auto socket2 = Socket(actual.family, actual.type, actual.protocol);
         socket2.connect(actual);

         // send using the connect socket
         auto remainder = buffer;
         while(remainder.length > 0) remainder = socket2.send(remainder);

         // send using the unconnected socket
         remainder = new byte[buffer.length];
         auto result = socket1.receiveFrom(remainder);
         assert(result.data == buffer);
         auto self = socket1.self;
         assert(result.address == self);
      }
   }

   /++
    +/
   const byte[] receive(byte[] buffer, int flags = 0)
   {
      enforce(isOpened);
      enforce(buffer.length > 0);

      auto size = recv(_socket.handle, buffer.ptr, buffer.length, flags);
      errnoEnforce(size != -1,
                   format("Socket.receive(byte[%x], %x)",
                          buffer.length,
                          flags));
      return buffer[0 .. size];
   }
   ///
   static struct ReceivedFrom
   {
      byte[] data;///
      immutable(Address) address;///
   }
   /// ditto
   const ReceivedFrom receiveFrom(byte[] buffer, int flags = 0)
   {
      enforce(isOpened);
      enforce(buffer.length > 0);

      sockaddr_storage addr;
      socklen_t len = typeof(addr).sizeof;
      auto size = recvfrom(_socket.handle,
                           buffer.ptr,
                           buffer.length,
                           flags,
                           cast(sockaddr*)&addr,
                           &len);

      immutable address = Address(_socket.family,
                                  _socket.type,
                                  _socket.protocol,
                                  addr,
                                  len);

      return ReceivedFrom(buffer[0 .. size], address); 
   }

   unittest
   {
      // === test receiving dgram messages ===
      auto addresses = Address.lookup("localhost",
                                      null,
                                      Family.unspec,
                                      Type.dgram);
      foreach(address; addresses)
      {
         byte[] buffer = ['H', 'e', 'l', 'l', 'o'];
         // create one end
         auto socket1 = Socket(address.family, address.type, address.protocol);
         socket1.bind(address);

         auto actual = socket1.self;
         auto socket2 = Socket(address.family, address.type, address.protocol);
         socket2.connect(actual);

         socket2.send(buffer);
         socket2.shutdown();
         assertThrown(socket2.send(buffer));
      }
   }

   /// 
   enum Operation
   {
      read = SHUT_RD, ///
      write = SHUT_WR, /// ditto
      both = SHUT_RDWR,/// ditto
   }
   /// ditto
   const void shutdown(Operation how = Operation.both)
   {
      enforce(isOpened);
      errnoEnforce(.shutdown(_socket.handle, how) == 0,
                   format("Socket.shutdown(%s) error:", to!string(how)));
   }

   /++
    +/
   void close()
   out
   {
      assert(!isOpened);
   }
   body
   {
      enforce(isOpened);
      scope(exit)
      {
         .close(_socket.handle);
         _socket.handle = 0;
      }

      try unregister();
      catch (Exception e) { /+ ignore exception +/ }
   }

   /++
    +/
   void register(Selector selector,
                 uint operations,
                 void delegate(Selector.Selection) handler)
   {
      enforce(isOpened);
      enforce(operations == Selector.READ ||
              operations == Selector.WRITE ||
              operations == (Selector.READ | Selector.WRITE));
      if(_socket.selector.canPromote)
      {
         auto oldSelector = _socket.selector.promote();
         if(oldSelector.isOpened) oldSelector.unregister(_socket.handle);
      }

      // register with new selector
      _socket.selector = Selector.Weak(selector);
      selector.register(this, operations, handler);
   }

   /++
    +/
   void unregister()
   {
      enforce(isOpened);
      if(_socket.selector.canPromote)
      {
         auto selector = _socket.selector.promote();
         if(selector.isOpened) selector.unregister(_socket.handle);
         _socket.selector = Selector.Weak.init;
      }
   }

   private static struct Impl
   {
      size_t refCount;

      // socket handle
      int handle;

      Family family;
      Type type;
      Protocol protocol;

      // selector registrations
      Selector.Weak selector;
   }

   private this(Family family, Type type, Protocol protocol)
   {
      auto handle = .socket(family, type, protocol);
      errnoEnforce(handle > 0,
                   format("Socket(%s, %s, %s) error:",
                          to!string(family),
                          to!string(type),
                          to!string(protocol)));

      this(handle, family, type, protocol);
   }

   private this(int handle, Family family, Type type, Protocol protocol)
   {
      auto pointer = cast(Impl*) calloc(1, Impl.sizeof);
      assert(pointer !is null);

      _socket = emplace(pointer, 1, handle, family, type, protocol);
      _token = TOKEN;
   }

   private const pure nothrow @property int handle()
   {
      assert(isOpened);
      return _socket.handle;
   }

   private Impl* _socket;
   private uint _token; // get around BUG 6178
}

unittest
{
   Socket[] sockets;
   byte[] buffer = ['H', 'e', 'l', 'l', 'o'];

   void clientHandler(Selector.Selection selection)
   {
      byte[512] temp;
      if(selection.operations & Selector.WRITE)
      {
         selection.socket.send(buffer);
         selection.socket.register(selection.selector,
                                   Selector.READ,
                                   &clientHandler);
      }
      else if(selection.operations & Selector.READ)
      {
         auto read = selection.socket.receive(temp);
         if(read.length == 0) selection.socket.close();
         else
         {
            assert(read == buffer);
            selection.socket.close();
         }
      }
      else assert(false);
   }

   void serverHandler(Selector.Selection selection)
   {
      byte[512] temp;
      if(selection.operations & Selector.READ)
      {
         auto read = selection.socket.receive(temp);
         if(read.length == 0) selection.socket.close();
         else
         {
            assert(read == buffer);
            selection.socket.register(selection.selector,
                                      Selector.WRITE,
                                      &serverHandler);
         }
      }
      else if(selection.operations & Selector.WRITE)
      {
         selection.socket.send(buffer);
         selection.socket.register(selection.selector,
                                   Selector.READ,
                                   &serverHandler);
      }
      else assert(false);
   }

   void acceptor(Selector.Selection selection)
   {
      auto peer = selection.socket.accept();
      peer.isBlocking = false;
      peer.register(selection.selector, Selector.READ, &serverHandler);
      ++sockets.length;
      sockets[$ - 1] = peer;
   }

   auto selector = Selector.selector();
   
   auto servers = Socket.streamServers("0", 10, false);
   foreach(server; servers)
   {
      server.register(selector, Selector.READ, &acceptor);
      auto client = Socket.streamClient(server.self.nodename,
                                        server.self.service,
                                        false);
      client.register(selector, Selector.WRITE, &clientHandler);
      ++sockets.length;
      sockets[$ - 1] = client;
   }

   Selector.Selection[124] selections;

   bool stop;
   do
   {
      stop = true;
      foreach(selection; selector.select(selections, dur!"hnsecs"(0)))
      {
         stop = false;
         selection.handler(selection);
      }
   } while(!stop)
}

/++
+/
struct Selector
{
   /++
    +/
   enum : uint
   {
      ///
      READ = 0x1,
      ///
      WRITE = 0x2,
      ///
      ERROR = 0x4,
   }

   /++
    +/
   static static struct Selection
   {
      Socket socket;
      Selector selector;
      uint operations;
      void delegate(Selection) handler;
   }

   /++
    +/
   static Selector selector() { return Selector(0); }

   this(this) { if(_selector !is null) ++_selector.refCount; }

   ~this()
   {
      if(_token == TOKEN && _selector !is null && --_selector.refCount == 0)
      {
         if(isOpened) close();
         if(_selector.weakCount == 0) free(_selector);
      }
      _selector = null;
      _token = 0;
   }

   ref Selector opAssign(Selector rhs)
   {
      swap(_selector, rhs._selector);
      swap(_token, rhs._token);
      return this;
   }

   /++
    +/
   const pure nothrow @property bool isOpened()
   {
      return _selector !is null && _selector.handle > 0;
   }

   /++
    +/
   Selection[] select(Selection[] selections, Duration timeout)
   {
      auto msecs = timeout.total!"msecs"();
      enforce(msecs <= int.max,
              format("Selection.select(Selection[%x], %s) error: " ~
                     "(Timeout larger than %x)",
                     selections.length,
                     to!string(timeout),
                     int.max));
      return select(selections, cast(int)timeout.total!"msecs"());
   }
   /// ditto
   Selection[] select(Selection[] selections)
   {
      return select(selections, -1);
   }

   /++
    +/
   void close()
   out
   {
      assert(!isOpened);
   }
   body
   {
      enforce(isOpened);
      scope(exit)
      {
         .close(_selector.handle);
         _selector.handle = 0;
      }

      // XXX: unregister every socket.
      // XXX: clear evertying in _selector
   }

   private this(int flags)
   {
      auto handle = epoll_create1(flags);
      errnoEnforce(handle > 0, format("Selector(%x) error:", flags));

      auto pointer = cast(Impl*) calloc(1, Impl.sizeof);
      assert(pointer !is null);

      _selector = emplace(pointer, 1, 0, handle);
      _token = TOKEN;
   }

   private this(Impl* impl)
   {
      assert(impl !is null);
      _selector = impl;
      _token = TOKEN;
      ++_selector.refCount;
   }

   private Selection[] select(Selection[] selections, int timeout)
   {
      enforce(isOpened);

      pure nothrow uint toEpollEvent(in uint events)
      {
         assert((events &
                 ~(Selector.READ | Selector.WRITE | Selector.ERROR)) == 0);

         uint result;
         if(events & READ) result |= EPOLLIN;
         if(events & WRITE) result |= EPOLLOUT;
         // EPOLLERR is set automatically

         return result;
      }

      pure nothrow uint toSelectorEvent(uint events)
      {
         // turn hang up event into read events
         if(events & EPOLLHUP)
         {
            events |= EPOLLIN;
            events &= ~EPOLLHUP;
         }

         assert((events & ~(EPOLLIN | EPOLLOUT | EPOLLERR)) == 0);

         uint result;
         if(events & EPOLLIN) result |= READ;
         if(events & EPOLLOUT) result |= WRITE;
         if(events & EPOLLERR) result |= ERROR;

         return result;
      }

      // update epoll's state
      foreach(handle, ref state; _selector.add)
      {
         epoll_event event;
         event.events = toEpollEvent(state.operations);
         event.data.fd = handle;
         errnoEnforce(epoll_ctl(_selector.handle,
                                EPOLL_CTL_ADD,
                                handle,
                                &event) == 0,
                      "Selector.select() error:");
         _selector.states[handle] = state;
      }
      _selector.add = null;

      foreach(handle, ref state; _selector.modify)
      {
         epoll_event event;
         event.events = toEpollEvent(state.operations);
         event.data.fd = handle;
         errnoEnforce(epoll_ctl(_selector.handle,
                                EPOLL_CTL_MOD,
                                handle,
                                &event) == 0,
                      "Selector.select() error:");
         _selector.states[handle] = state;
      }
      _selector.modify = null;

      _selector.events.length = selections.length;
      auto size = epoll_wait(_selector.handle,
                             _selector.events.ptr,
                             _selector.events.length,
                             timeout);
      errnoEnforce(size != -1, "Selector.select() error:");

      Selection[] result = selections[0 .. size];
      foreach(i; 0 .. size)
      {
         auto state = _selector.states[_selector.events[i].data.fd];
         result[i] = Selection(state.socket,
                               this,
                               toSelectorEvent(_selector.events[i].events),
                               state.handler);
      }

      return result;
   }


   private void register(Socket socket,
                         uint operations,
                         void delegate(Selection) handler)
   {
      enforce(isOpened);
      if(!(socket.handle in _selector.states))
      {
         _selector.add[socket.handle] = Impl.State(socket.handle,
                                                   socket,
                                                   operations,
                                                   handler); 
      }
      else 
      {
         _selector.modify[socket.handle] = Impl.State(socket.handle,
                                                      socket,
                                                      operations,
                                                      handler);
      }
   }

   private void unregister(int socketHandle)
   {
      enforce(isOpened);
      if(!(socketHandle in _selector.states))
      {
         _selector.add.remove(socketHandle);
      }
      else
      {
         // unregister may come from an invalid handle. must remove directly
         // and not cache the operation.
         _selector.modify.remove(socketHandle);
         _selector.states.remove(socketHandle);

         epoll_event event; // need this because of a bug in Linux 2.6.9
         errnoEnforce(epoll_ctl(_selector.handle,
                                EPOLL_CTL_DEL,
                                socketHandle,
                                &event) == 0,
                      "Selector.select() error:");
      }
   }

   private static struct Weak
   {
      this(Selector selector)
      {
         _selector = selector._selector;
         if(_selector !is null) ++_selector.weakCount;
      }

      this(this)
      {
         if(_selector !is null) ++_selector.weakCount;
      }

      ~this()
      {
         if(_selector !is null &&
            --_selector.weakCount == 0 &&
            _selector.refCount == 0)
         {
            free(_selector);
         }
         _selector = null;
      }

      ref Weak opAssign(Weak weak)
      {
         swap(_selector, weak._selector);
         return this;
      }

      nothrow @property bool canPromote()
      {
         if(_selector !is null)
         {
            if(_selector.refCount > 0) return true;

            assert(_selector.refCount == 0);
            if(--_selector.weakCount == 0)
            {
               free(_selector);
               _selector = null;
            }
         }

         return false;
      }

      Selector promote()
      {
         enforce(canPromote);
         return Selector(_selector);
      }

      private Impl* _selector;
   }

   private struct Impl 
   {
      struct State
      {
         int key;
         Socket socket;
         uint operations;
         void delegate(Selection) handler;
      }

      size_t refCount;
      size_t weakCount;

      int handle;
      epoll_event[] events;

      State[int] states;

      State[int] add;
      State[int] modify;
   }

   private Impl* _selector;
   private uint _token; // get around BUG 6178
}
