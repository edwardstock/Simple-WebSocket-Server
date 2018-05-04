#ifndef SERVER_WSS_HPP
#define SERVER_WSS_HPP

#include "server_ws.hpp"
#include <algorithm>
#include <openssl/ssl.h>

#ifdef USE_STANDALONE_ASIO
#include <asio/ssl.hpp>
#else
#include <boost/asio/ssl.hpp>
#endif

namespace SimpleWeb {
using WSS = asio::ssl::stream<asio::ip::tcp::socket>;

template<>
class SocketServer<WSS> : public SocketServerBase<WSS> {
    std::string sessionIdContext;
    bool setSessionIdContext = false;

 public:
    SocketServer(const std::string &certFile,
                 const std::string &privateKeyFile,
                 const std::string &verifyFile = std::string())
        : SocketServerBase<WSS>(443), context(asio::ssl::context::tlsv12) {
        context.use_certificate_chain_file(certFile);
        context.use_private_key_file(privateKeyFile, asio::ssl::context::pem);
        context.set_options(SSL_OP_NO_COMPRESSION);

        if (verifyFile.size() > 0) {
            context.load_verify_file(verifyFile);
            context.set_verify_mode(asio::ssl::verify_peer | asio::ssl::verify_fail_if_no_peer_cert |
                asio::ssl::verify_client_once);
            setSessionIdContext = true;
        }
    }

    void start() override {
        if (setSessionIdContext) {
            // Creating sessionIdContext from address:port but reversed due to small SSL_MAX_SSL_SESSION_ID_LENGTH
            sessionIdContext = std::to_string(config.port) + ':';
            sessionIdContext.append(config.address.rbegin(), config.address.rend());

            SSL_CTX_set_session_id_context(
                context.native_handle(),
                reinterpret_cast<const unsigned char *>(sessionIdContext.data()),
                (unsigned int) std::min<std::size_t>(sessionIdContext.size(), SSL_MAX_SSL_SESSION_ID_LENGTH)
            );
        }
        SocketServerBase::start();
    }

 protected:
    asio::ssl::context context;

    void accept() override {
        std::shared_ptr<Connection> connection(new Connection(handlerRunner, config.timeoutIdle, *ioService, context));

        acceptor->async_accept(connection->socket->lowest_layer(), [this, connection](const ErrorCode &ec) {
          auto lock = connection->handlerRunner->continueLock();
          if (!lock) {
              return;
          }

          // Immediately start accepting a new connection (if ioService hasn't been stopped)
          if (ec != asio::error::operation_aborted) {
              accept();
          }

          if (!ec) {
              asio::ip::tcp::no_delay option(true);
              connection->socket->lowest_layer().set_option(option);

              connection->timeoutSet(config.timeoutRequest);
              connection->socket
                        ->async_handshake(asio::ssl::stream_base::server, [this, connection](const ErrorCode &ec) {
                          auto sublock = connection->handlerRunner->continueLock();
                          if (!sublock) {
                              return;
                          }

                          connection->timeoutCancel();
                          if (!ec)
                              handshakeRead(connection);
                        });
          }
        });
    }
};
} // namespace SimpleWeb

#endif /* SERVER_WSS_HPP */
