// Copyright (c) 2025 Nexalt Core contributors
// Distributed under the MIT software license.

#include <mlcdb.h>

#include <util/system.h>
#include <logging.h>

#include "leveldb/db.h"
#include "leveldb/cache.h"
#include "leveldb/options.h"
#include "leveldb/filter_policy.h"

// ----------------- StringLruCache -----------------

StringLruCache::StringLruCache(size_t capacityEntries)
    : m_capacity(capacityEntries) {}

bool StringLruCache::get(const std::string& key, std::string& value) {
    auto it = m_map.find(key);
    if (it == m_map.end()) return false;
    // move to front (MRU)
    m_list.splice(m_list.begin(), m_list, it->second);
    value = it->second->second;
    return true;
}

void StringLruCache::put(const std::string& key, const std::string& value) {
    auto it = m_map.find(key);
    if (it != m_map.end()) {
        it->second->second = value;
        m_list.splice(m_list.begin(), m_list, it->second);
        return;
    }
    m_list.emplace_front(key, value);
    m_map[key] = m_list.begin();
    if (m_map.size() > m_capacity) {
        auto& back = m_list.back();
        m_map.erase(back.first);
        m_list.pop_back();
    }
}

void StringLruCache::clear() {
    m_list.clear();
    m_map.clear();
}

// ----------------- MlcDb -----------------

MlcDb& MlcDb::Instance() {
    static MlcDb instance;
    return instance;
}

MlcDb::MlcDb()
    : m_mlcDb(nullptr), m_myKeyDb(nullptr), m_blockCache(nullptr),
      m_mlcCache(500000), // ~500k hot keys (tune with memory)
      m_myKeyCache(10000), // wallet-scope is much smaller
      m_opened(false),
      m_filter(nullptr) {}

MlcDb::~MlcDb() {
    // Intentionally leak on shutdown like Bitcoin logging to avoid dtor order issues
}

void MlcDb::EnsureOpen() {
    if (m_opened) return;
    std::lock_guard<std::mutex> g(m_openMutex);
    if (!m_opened) OpenLocked();
}

void MlcDb::OpenLocked() {
    // Prepare options
    leveldb::Options opts;
    opts.create_if_missing = true;
    // Use a shared block cache to reduce disk reads
    if (!m_blockCache) m_blockCache = leveldb::NewLRUCache(64 * 1024 * 1024); // 64MB
    opts.block_cache = m_blockCache;
    // Add bloom filter to reduce disk seeks on negative lookups
    if (!m_filter) m_filter = leveldb::NewBloomFilterPolicy(10);
    opts.filter_policy = m_filter;

    const std::string dataDir = GetDataDir().string();
    const std::string mlcPath = dataDir + "/mlc";
    const std::string myKeyPath = dataDir + "/myKey";

    leveldb::DB* mlcDb = nullptr;
    leveldb::DB* myDb = nullptr;

    leveldb::Status s1 = leveldb::DB::Open(opts, mlcPath, &mlcDb);
    if (!s1.ok()) {
        LogPrintf("[MLCDB] Failed to open %s: %s\n", mlcPath, s1.ToString());
        // Do not mark opened; reads/writes will no-op/fail gracefully
        return;
    }
    leveldb::Status s2 = leveldb::DB::Open(opts, myKeyPath, &myDb);
    if (!s2.ok()) {
        LogPrintf("[MLCDB] Failed to open %s: %s\n", myKeyPath, s2.ToString());
        delete mlcDb;
        return;
    }

    m_mlcDb = mlcDb;
    m_myKeyDb = myDb;
    m_opened = true;
    LogPrintf("[MLCDB] Opened persistent DBs at %s and %s\n", mlcPath, myKeyPath);
}

bool MlcDb::GetMlc(const std::string& key, std::string& value) {
    EnsureOpen();
    if (!m_mlcDb) return false;
    {
        std::lock_guard<std::mutex> g(m_mlcMutex);
        if (m_mlcCache.get(key, value)) return true;
        leveldb::ReadOptions ro;
        ro.fill_cache = true;
        leveldb::Status s = m_mlcDb->Get(ro, key, &value);
        if (!s.ok()) return false;
        m_mlcCache.put(key, value);
        return true;
    }
}

bool MlcDb::PutMlc(const std::string& key, const std::string& value) {
    EnsureOpen();
    if (!m_mlcDb) return false;
    std::lock_guard<std::mutex> g(m_mlcMutex);
    leveldb::WriteOptions wo;
    wo.sync = false; // Preserve prior behavior (no explicit fsyncs were used)
    leveldb::Status s = m_mlcDb->Put(wo, key, value);
    if (s.ok()) m_mlcCache.put(key, value);
    return s.ok();
}

bool MlcDb::GetMyKey(const std::string& key, std::string& value) {
    EnsureOpen();
    if (!m_myKeyDb) return false;
    {
        std::lock_guard<std::mutex> g(m_myMutex);
        if (m_myKeyCache.get(key, value)) return true;
        leveldb::ReadOptions ro;
        ro.fill_cache = true;
        leveldb::Status s = m_myKeyDb->Get(ro, key, &value);
        if (!s.ok()) return false;
        m_myKeyCache.put(key, value);
        return true;
    }
}

bool MlcDb::PutMyKey(const std::string& key, const std::string& value) {
    EnsureOpen();
    if (!m_myKeyDb) return false;
    std::lock_guard<std::mutex> g(m_myMutex);
    leveldb::WriteOptions wo;
    wo.sync = false; // preserve previous semantics
    leveldb::Status s = m_myKeyDb->Put(wo, key, value);
    if (s.ok()) m_myKeyCache.put(key, value);
    return s.ok();
}

void MlcDb::ClearCaches() {
    std::lock_guard<std::mutex> g1(m_mlcMutex);
    std::lock_guard<std::mutex> g2(m_myMutex);
    m_mlcCache.clear();
    m_myKeyCache.clear();
}


