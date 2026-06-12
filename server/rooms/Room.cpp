#include "Room.h"
#include <mutex>
#include <shared_mutex>

Room::Room(const std::string& name, const std::string& creator)
    : m_name(name), m_topic(""), m_creator(creator),
      m_createdAt(std::time(nullptr)), m_isPrivate(false), m_maxMembers(50) {}

void Room::addMember(int fd) {
    std::unique_lock<std::shared_mutex> lk(m_mutex);
    m_members.insert(fd);
}

void Room::removeMember(int fd) {
    std::unique_lock<std::shared_mutex> lk(m_mutex);
    m_members.erase(fd);
}

bool Room::isMember(int fd) const {
    std::shared_lock<std::shared_mutex> lk(m_mutex);
    return m_members.count(fd) > 0;
}

bool Room::isFull() const {
    std::shared_lock<std::shared_mutex> lk(m_mutex);
    return (int)m_members.size() >= m_maxMembers;
}

int Room::getMemberCount() const {
    std::shared_lock<std::shared_mutex> lk(m_mutex);
    return (int)m_members.size();
}

std::set<int> Room::getMembers() const {
    std::shared_lock<std::shared_mutex> lk(m_mutex);
    return m_members;
}

std::vector<std::string> Room::getMemberNicknames(
    const std::function<std::string(int)>& resolver) const
{
    std::shared_lock<std::shared_mutex> lk(m_mutex);
    std::vector<std::string> result;
    for (int fd : m_members) {
        auto n = resolver(fd);
        if (!n.empty()) result.push_back(n);
    }
    return result;
}
