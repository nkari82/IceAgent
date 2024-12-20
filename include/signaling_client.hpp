// include/signaling_client.hpp

#ifndef SIGNALING_CLIENT_HPP
#define SIGNALING_CLIENT_HPP

#include <asio.hpp>
#include <websocketpp/config/asio_no_tls_client.hpp>
#include <websocketpp/client.hpp>
#include <nlohmann/json.hpp>
#include <functional>
#include <memory>
#include <string>

// JSON 라이브러리 사용
using json = nlohmann::json;
typedef websocketpp::client<websocketpp::config::asio_client> WebSocketClient;

// Forward 선언
class IceAgent;

// SignalingClient 클래스 정의
class SignalingClient : public std::enable_shared_from_this<SignalingClient> {
public:
    SignalingClient(asio::io_context& io_context, const std::string& uri, std::shared_ptr<IceAgent> ice_agent);
    void connect();
    void run();
    void send_message(const std::string& message);

private:
    WebSocketClient ws_client_;
    websocketpp::connection_hdl connection_;
    std::string uri_;
    asio::io_context& io_context_;
    std::shared_ptr<IceAgent> ice_agent_;

    void on_message(websocketpp::connection_hdl hdl, WebSocketClient::message_ptr msg);
    void on_open(websocketpp::connection_hdl hdl);
    void on_fail(websocketpp::connection_hdl hdl);
};

#endif // SIGNALING_CLIENT_HPP
