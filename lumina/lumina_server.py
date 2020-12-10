#!/usr/bin/python3

import os, sys, argparse, logging, signal, threading

from socketserver import ThreadingMixIn, TCPServer, BaseRequestHandler
import socket, ssl

try:
    from lumina.lumina_structs import rpc_message_parse, rpc_message_build, RPC_TYPE
    from lumina.database import LuminaDatabase
except ImportError:
    # local import for standalone use
    from lumina_structs import rpc_message_parse, rpc_message_build, RPC_TYPE
    from database import LuminaDatabase


################################################################################
#
# Protocole
#
################################################################################

class LuminaRequestHandler(BaseRequestHandler):
    def __init__(self, request, client_address, server):
        self.logger = server.logger
        self.database = server.database
        super().__init__(request, client_address, server)


    def sendMessage(self, code, **kwargs):
        self.logger.debug(f"sending RPC Packet (code = {code}, data={kwargs}")

        data = rpc_message_build(code, **kwargs)
        self.request.send(data)

    def recvMessage(self):
        packet, message = rpc_message_parse(self.request)
        self.logger.debug(f"got new RPC Packet (code = {packet.code}, data={message}")
        return packet, message

    def handle(self):

        #
        # Get first RPC packet (RPC_HELO)
        #

        packet, message = self.recvMessage()

        if packet.code != RPC_TYPE.RPC_HELO:
            self.sendMessage(RPC_TYPE.RPC_NOTIFY, message = 'Expected helo')
            return

        if self.server.check_client(message):
            self.sendMessage(RPC_TYPE.RPC_OK)
        else:
            self.sendMessage(RPC_TYPE.RPC_NOTIFY, message = 'Invalid license')
            return

        #
        # Receive and handle request command:
        #
        packet, message = self.recvMessage()

        if packet.code == RPC_TYPE.PUSH_MD:
            results = list()
            for _, info in enumerate(message.funcInfos):
                results.append(self.database.push(info))

            self.sendMessage(RPC_TYPE.PUSH_MD_RESULT, resultsFlags = results)

        elif packet.code == RPC_TYPE.PULL_MD:
            found = list()
            results = list()

            for sig in message.funcInfos:
                metadata = self.database.pull(sig)
                if metadata:
                    found.append(1)
                    results.append(metadata)
                else:
                    found.append(0)

            self.sendMessage(RPC_TYPE.PULL_MD_RESULT, found = found, results =results)

        else:
            self.logger("[-] ERROR: message handler not implemented")
            self.sendMessage(RPC_TYPE.RPC_NOTIFY, message = "Unknown command")
            #self.sendMessage(RPC_TYPE.RPC_FAIL, status = -1, message = "not implemented")

        return

class LuminaServer(ThreadingMixIn, TCPServer):
    def __init__(self, database, config, logger, bind_and_activate=True):
        super().__init__((config.ip, config.port), LuminaRequestHandler, bind_and_activate)
        self.config = config
        self.database = database
        self.logger = logger
        self.useTLS = False

        if self.config.cert:
            if self.config.cert_key is None:
                raise ValueError("Missing certificate key argument")

            self.useTLS = True

    def get_request(self):
        client_socket, fromaddr = self.socket.accept()

        self.logger.debug(f"new client {fromaddr[0]}:{fromaddr[1]}")
        if not self.useTLS:
            self.logger.debug("Starting plaintext session")
            # extra check: make sure client does no try to initiate a TLS session (or parsing would hang)
            data = client_socket.recv(3, socket.MSG_PEEK)
            if data == b'\x16\x03\x01':
                self.logger.error("TLS client HELLO detected on plaintext mode. Check IDA configuration and cert. Aborting")
                client_socket.close()
                raise OSError("NO TLS")

        if self.useTLS:
            self.logger.debug("Starting TLS session")
            try:
                client_socket = ssl.wrap_socket(client_socket,
                                                ssl_version = ssl.PROTOCOL_TLSv1_2,
                                                server_side = True,
                                                certfile=self.config.cert.name,
                                                keyfile=self.config.cert_key.name)

            except Exception:
                self.logger.exception("TLS connection failed. Check IDA configuration and cert")
                raise

        return client_socket, fromaddr

    def shutdown(self, save=True):
        self.logger.info("Server stopped")
        super().shutdown()
        self.database.close(save=save)

    def serve_forever(self):
        self.logger.info(f"Server started. Listening on {self.server_address[0]}:{self.server_address[1]} (TLS={'ON' if self.useTLS else 'OFF'})")
        super().serve_forever()

    def check_client(self, message):
        """
        Return True if user is authozied, else False
        """
        # check (message.hexrays_licence, message.hexrays_id, message.watermak, message.field_0x36)
        self.logger.debug("RPC client accepted")
        return True

def signal_handler(sig, frame, server):
    print('Ctrl+C caught. Exiting')
    server.shutdown(save=True)
    sys.exit(0)


def main():
    # default log handler is stdout. You can add a FileHandler or any handler you want
    log_handler = logging.StreamHandler(sys.stdout)
    log_handler.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s"))
    logger = logging.getLogger("lumina")
    logger.addHandler(log_handler)
    logger.setLevel(logging.DEBUG)

    # Parse command line
    parser = argparse.ArgumentParser()
    parser.add_argument("db", type=argparse.FileType('a+'), default="", help="database file")
    parser.add_argument("-i", "--ip", dest="ip", type=str, default="127.0.0.1", help="listening ip address (default: 127.0.0.1")
    parser.add_argument("-p", "--port", dest="port", type=int, default=4443, help="listening port (default: 4443")
    parser.add_argument("-c", "--cert", dest="cert", type=argparse.FileType('r'), default = None, help="proxy certfile (no cert means TLS OFF).")
    parser.add_argument("-k", "--key", dest="cert_key",type=argparse.FileType('r'), default = None, help="certificate private key")
    parser.add_argument("-l", "--log", dest="log_level", type=str, choices=["NOTSET", "DEBUG", "INFO", "WARNING"], default="INFO", help="log level bases on python logging value (default:info)")
    config = parser.parse_args()


    logger.setLevel(config.log_level)

    # create db & server
    database = LuminaDatabase(logger, config.db)
    TCPServer.allow_reuse_address = True
    server = LuminaServer(database, config, logger)

    # set ctrl-c handler
    signal.signal(signal.SIGINT, lambda sig,frame:signal_handler(sig, frame, server))

    # start server
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = False
    server_thread.start()
    server_thread.join()

    server.database.close(save=True)

if __name__ == "__main__":
    main()