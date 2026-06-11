#pragma once
#include <iostream>
#include <string>
#include <stdexcept>

namespace test {
    static int s_passed = 0;
    static int s_failed = 0;

    #define ASSERT_TRUE(condition) \
        if (!(condition)) { \
            std::cerr << "[\033[31mFAIL\033[0m] " << __FUNCTION__ << ":" << __LINE__ << " -> Expected true, got false (" << #condition << ")\n"; \
            test::s_failed++; \
        } else { \
            test::s_passed++; \
        }

    #define ASSERT_FALSE(condition) \
        if ((condition)) { \
            std::cerr << "[\033[31mFAIL\033[0m] " << __FUNCTION__ << ":" << __LINE__ << " -> Expected false, got true (" << #condition << ")\n"; \
            test::s_failed++; \
        } else { \
            test::s_passed++; \
        }

    #define ASSERT_EQ(actual, expected) \
        if (!((actual) == (expected))) { \
            std::cerr << "[\033[31mFAIL\033[0m] " << __FUNCTION__ << ":" << __LINE__ << " -> Expected " << (expected) << ", got " << (actual) << "\n"; \
            test::s_failed++; \
        } else { \
            test::s_passed++; \
        }

    #define ASSERT_NEQ(actual, expected) \
        if (((actual) == (expected))) { \
            std::cerr << "[\033[31mFAIL\033[0m] " << __FUNCTION__ << ":" << __LINE__ << " -> Expected not " << (expected) << ", got " << (actual) << "\n"; \
            test::s_failed++; \
        } else { \
            test::s_passed++; \
        }

    #define ASSERT_THROWS(expr, exception_type) \
        { \
            bool threw = false; \
            try { (expr); } \
            catch (const exception_type&) { threw = true; test::s_passed++; } \
            catch (...) { std::cerr << "[\033[31mFAIL\033[0m] " << __FUNCTION__ << ":" << __LINE__ << " -> Threw wrong type\n"; test::s_failed++; threw = true; } \
            if (!threw) { std::cerr << "[\033[31mFAIL\033[0m] " << __FUNCTION__ << ":" << __LINE__ << " -> Did not throw\n"; test::s_failed++; } \
        }

    #define RUN_TEST(test_func) \
        std::cout << "[RUN ] " << #test_func << "\n"; \
        try { \
            test_func(); \
        } catch (const std::exception& e) { \
            std::cerr << "[\033[31mFAIL\033[0m] " << #test_func << " -> Unhandled exception: " << e.what() << "\n"; \
            test::s_failed++; \
        } catch (...) { \
            std::cerr << "[\033[31mFAIL\033[0m] " << #test_func << " -> Unhandled unknown exception\n"; \
            test::s_failed++; \
        }

    inline int PrintTestResults(const std::string& suite_name) {
        std::cout << "\n=========================================\n";
        std::cout << "Test Suite: " << suite_name << "\n";
        std::cout << "Passed: \033[32m" << test::s_passed << "\033[0m\n";
        if (test::s_failed > 0) {
            std::cout << "Failed: \033[31m" << test::s_failed << "\033[0m\n";
        }
        std::cout << "=========================================\n";
        return test::s_failed > 0 ? 1 : 0;
    }
}
