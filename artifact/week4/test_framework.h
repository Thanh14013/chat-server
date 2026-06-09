#pragma once
#include <iostream>
#include <string>
#include <vector>
#include <functional>
#include <stdexcept>

struct TestCase {
    std::string            name;
    std::function<void()>  fn;
};

static std::vector<TestCase> g_tests;
static int g_passed = 0;
static int g_failed = 0;

#define TEST(name) \
    static void test_##name(); \
    static struct _reg_##name { \
        _reg_##name() { g_tests.push_back({#name, test_##name}); } \
    } _r_##name; \
    static void test_##name()

#define ASSERT_TRUE(expr) \
    do { if (!(expr)) throw std::runtime_error("ASSERT_TRUE failed: " #expr); } while(0)

#define ASSERT_FALSE(expr) \
    do { if (expr) throw std::runtime_error("ASSERT_FALSE failed: " #expr); } while(0)

#define ASSERT_EQ(a, b) \
    do { if ((a) != (b)) throw std::runtime_error( \
        std::string("ASSERT_EQ failed: ") + #a + " != " + #b); } while(0)

#define ASSERT_NE(a, b) \
    do { if ((a) == (b)) throw std::runtime_error( \
        std::string("ASSERT_NE failed: ") + #a + " == " + #b); } while(0)

#define ASSERT_THROWS(expr) \
    do { bool threw = false; try { expr; } catch(...) { threw = true; } \
    if (!threw) throw std::runtime_error("ASSERT_THROWS: no exception: " #expr); } while(0)

static int run_all_tests(const std::string& suite) {
    std::cout << "\n=== " << suite << " ===\n";
    for (auto& tc : g_tests) {
        try {
            tc.fn();
            std::cout << "  [PASS] " << tc.name << "\n";
            g_passed++;
        } catch (const std::exception& e) {
            std::cout << "  [FAIL] " << tc.name << " — " << e.what() << "\n";
            g_failed++;
        }
    }
    std::cout << "\nResult: " << g_passed << " passed, " << g_failed << " failed\n";
    return g_failed == 0 ? 0 : 1;
}
