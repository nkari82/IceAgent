#include <asio.hpp>
#include <atomic>
#include <chrono>
#include <iostream>
#include <mutex>
#include <unordered_map>
#include <vector>

using asio::awaitable;
using asio::use_awaitable;
using asio::ip::udp;

class TestClass {
   private:
    asio::io_context& io_context_;
    udp::socket udp_socket_;
    std::atomic<int> id_{0};

    struct ResponseData {
        std::optional<std::string> data;
        asio::steady_timer timer;  // 응답 대기를 위한 타이머

        ResponseData(asio::io_context& ctx, std::chrono::seconds timeout) : timer(ctx, timeout) {}
    };

    std::unordered_map<int, std::shared_ptr<ResponseData>> pending_responses_;
    std::mutex response_mutex_;  // 응답 맵 보호

   public:
    TestClass(asio::io_context& context) : io_context_(context), udp_socket_(context, udp::endpoint(udp::v4(), 0)) {}

    void start() {
        asio::co_spawn(io_context_, [this] { return ReceiveData(); }, asio::detached);
    }

    awaitable<std::optional<std::string>> SendWithTimer(int max_retries = 3,
                                                        std::chrono::seconds timeout = std::chrono::seconds(5)) {
        udp::endpoint target(asio::ip::make_address("127.0.0.1"), 12345);

        int id = ++id_;
        std::string payload = "Payload data";

        std::vector<uint8_t> send_buffer(sizeof(int) + payload.size());
        std::memcpy(send_buffer.data(), &id, sizeof(int));
        std::memcpy(send_buffer.data() + sizeof(int), payload.data(), payload.size());

        for (int attempt = 1; attempt <= max_retries; ++attempt) {
            auto response = std::make_shared<ResponseData>(io_context_, timeout);

            {
                std::lock_guard<std::mutex> lock(response_mutex_);
                pending_responses_.emplace(id, response);
            }

            std::cout << "Sending request with ID " << id << " (Attempt " << attempt << " of " << max_retries << ")"
                      << std::endl;

            co_await udp_socket_.async_send_to(asio::buffer(send_buffer), target, use_awaitable);

            // 타이머 대기
            asio::error_code ec;
            co_await response->timer.async_wait(asio::redirect_error(use_awaitable, ec));

            {
                std::lock_guard<std::mutex> lock(response_mutex_);
                auto it = pending_responses_.find(id);
                if (it != pending_responses_.end() && it->second->data) {
                    // 응답 도착
                    std::cout << "Received response for ID " << id << ": " << *it->second->data << std::endl;
                    pending_responses_.erase(it);
                    co_return it->second->data;
                }
            }

            // 타임아웃 처리
            if (ec == asio::error::operation_aborted) {
                // 타이머 취소(응답 도착)
                continue;
            } else {
                std::cerr << "Timeout waiting for response for ID " << id << " (Attempt " << attempt << ")"
                          << std::endl;

                {
                    std::lock_guard<std::mutex> lock(response_mutex_);
                    pending_responses_.erase(id);
                }

                if (attempt == max_retries) {
                    std::cerr << "All retry attempts failed for ID " << id << std::endl;
                    co_return std::nullopt;
                }
            }
        }

        co_return std::nullopt;
    }

    awaitable<void> ReceiveData() {
        std::vector<uint8_t> buf(2048);

        while (true) {
            udp::endpoint sender;
            size_t bytes_received = co_await udp_socket_.async_receive_from(asio::buffer(buf), sender, use_awaitable);

            if (bytes_received < sizeof(int)) {
                std::cerr << "Received invalid packet\n";
                continue;
            }

            int received_id;
            std::memcpy(&received_id, buf.data(), sizeof(int));

            std::string received_data(reinterpret_cast<char*>(buf.data() + sizeof(int)), bytes_received - sizeof(int));

            {
                std::lock_guard<std::mutex> lock(response_mutex_);
                auto it = pending_responses_.find(received_id);
                if (it != pending_responses_.end()) {
                    auto& response = it->second;
                    response->data = received_data;

                    // 타이머 취소하여 대기 중인 코루틴 재개
                    response->timer.cancel();
                    std::cout << "Processed response for ID " << received_id << ": " << received_data << std::endl;
                } else {
                    std::cerr << "Received response for unknown ID: " << received_id << std::endl;
                }
            }
        }
    }
};
