/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <vector>

#include <gtest/gtest.h>

#include <boost/tokenizer.hpp>

#include "osquery/events/linux/http_event_publisher.h"
#include "osquery/tests/test_util.h"
#include "osquery/tests/integration/tables/helper.h"


#include <stdio.h>

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>

#include <gflags/gflags.h>
#include <gtest/gtest.h>

#include <osquery/database.h>
#include <osquery/events.h>
#include <osquery/events/linux/inotify.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/registry_factory.h>
#include <osquery/tables.h>
#include <osquery/utils/info/tool_type.h>


namespace osquery {
DECLARE_bool(disable_database);
DECLARE_bool(enable_http_lookups);

class HTTPEventsTests : public testing::Test {
 protected:
  void SetUp() override {
    kToolType = ToolType::TEST;
    registryAndPluginInit();

    FLAGS_disable_database = true;
    FLAGS_enable_http_lookups = true;
    DatabasePlugin::setAllowOpen(true);
    DatabasePlugin::initPlugin();
  }
  void StartEventLoop() {
    event_pub_ = std::make_shared<HTTPLookupEventPublisher>();
    auto status = EventFactory::registerEventPublisher(event_pub_);
    event_pub_->configure();
    ::usleep(1000);
    temp_thread_ = std::thread(EventFactory::run, "http_lookups");
    ::usleep(1000);

    return;
  }

  void StopEventLoop() {
    while (!event_pub_->hasStarted()) {
      ::usleep(20);
    }
    ::usleep(1000);
    EventFactory::end(true);
    temp_thread_.join();
  }

 protected:
  /// Internal state managers: publisher reference.
  std::shared_ptr<HTTPLookupEventPublisher> event_pub_{nullptr};

  /// Internal state managers: event publisher thread.
  std::thread temp_thread_;
};



class TestHTTPEventSubscriber
    : public EventSubscriber<HTTPLookupEventPublisher> {
 public:
  TestHTTPEventSubscriber() {
    setName("TestHTTPEventSubscriber");
  }

  Status init() override {
    callback_count_ = 0;
    return Status::success();
  }

  Status Callback(const ECRef& ec, const SCRef& sc);

  void WaitForEvents(int max, int num_events = 1) {
    int delay = 0;
    while (delay < max * 1000) {
      if (callback_count_ >= num_events) {
        return;
      }
      ::usleep(50);
      delay += 50;
    }
  }
 public:
  std::atomic<int> callback_count_{0};
 private:
  FRIEND_TEST(HTTPEventsTests, test_HTTP_events);
};

Status TestHTTPEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
    EXPECT_STRCASEEQ("empidoidea.info", ec->host.c_str());
    EXPECT_STRCASEEQ("GET", ec->method.c_str());
    EXPECT_STRCASEEQ("157.140.2.32", ec->remote.c_str());
    EXPECT_STRCASEEQ("", ec->protocol.c_str());
    EXPECT_STRCASEEQ("/gallery", ec->uri.c_str());
    EXPECT_EQ(80, ec->d_port);
    callback_count_++;
    return Status(0, "OK");
}

TEST_F(HTTPEventsTests, test_HTTP_events) {
  StartEventLoop();

  auto sub = std::make_shared<TestHTTPEventSubscriber>();
  EventFactory::registerEventSubscriber(sub);
  auto sc = sub->createSubscriptionContext();
  EventFactory::addSubscription("http_lookups", "TestHTTPEventSubscriber", sc);
  sub->subscribe(&TestHTTPEventSubscriber::Callback, sc);
  //Fire an event 
  table_tests::execute_query("select * from curl where url = 'http://empidoidea.info/gallery'");
  //Wait until the http parameter gets validated.
  sub->WaitForEvents(5);
  StopEventLoop();
}
}
