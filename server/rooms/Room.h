#pragma once
#include <string>
#include <set>
#include <vector>
#include <functional>
#include <shared_mutex>
#include <ctime>

class Room
{
public:
    Room(const std::string &name, const std::string &creator);

    void addMember(int fd);
    void removeMember(int fd);
    bool isMember(int fd) const;
    bool isFull() const;
    int getMemberCount() const;
    std::set<int> getMembers() const;

    std::vector<std::string> getMemberNicknames(const std::function<std::string(int)> &resolver) const;

    const std::string &name() const { return m_name; }
    const std::string &topic() const { return m_topic; }
    const std::string &creator() const { return m_creator; }
    bool isPrivate() const { return m_isPrivate; }
    time_t createdAt() const { return m_createdAt; }
    bool hasPassword() const { return !m_password.empty(); }
    bool checkPassword(const std::string &p) const { return m_password == p; }

    void setTopic(const std::string& t)      { m_topic = t; }
    void setPrivate(bool v)                  { m_isPrivate = v; }
    void setPassword(const std::string& p)   { m_password = p; }
    void setMaxMembers(int m)                { m_maxMembers = m; }
private:
    std::string               m_name;
    std::string               m_topic;
    std::string               m_creator;
    std::set<int>             m_members;
    time_t                    m_createdAt;
    bool                      m_isPrivate;
    std::string               m_password;
    int                       m_maxMembers;
    mutable std::shared_mutex m_mutex;   
};