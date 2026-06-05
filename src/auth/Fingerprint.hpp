#pragma once

#include "Auth.hpp"

#include <memory>
#include <optional>
#include <string>
#include <cstdint>
#include <sdbus-c++/sdbus-c++.h>

class CFingerprint : public IAuthImplementation {
  public:
    CFingerprint();

    virtual ~CFingerprint();
    virtual eAuthImplementations getImplType() {
        return AUTH_IMPL_FINGERPRINT;
    }
    virtual void                       init();
    virtual void                       handleInput(const std::string& input);
    virtual bool                       checkWaiting();
    virtual std::optional<std::string> getLastFailText();
    virtual std::optional<std::string> getLastPrompt();
    virtual void                       terminate();

  private:
    struct SDBUSState {
        std::unique_ptr<sdbus::IProxy> device;

        bool                           abort     = false;
        bool                           done      = false;
        int                            retries   = 0;
        bool                           sleeping         = false;
        bool                           verifying        = false;
        bool                           claiming         = false;
        bool                           claimed          = false;
        bool                           verifyStarted    = false;
        bool                           releasing        = false;
        bool                           startScheduled   = false;
        bool                           sleepSignalSeen  = false;
        uint64_t                       deviceGeneration = 0;
    } m_sDBUSState;

    std::string m_sFingerprintReady;
    std::string m_sFingerprintPresent;
    int         m_iVerificationTimeout = 0;

    std::string m_sPrompt{""};
    std::string m_sFailureReason{""};

    ASP<CTimer> m_pRefreshTimer;

    void        handleVerifyStatus(const std::string& result, const bool done);

    bool        createDeviceProxy();
    void        dropDeviceProxy();
    void        claimDevice();
    void        scheduleStartVerify();
    void        scheduleRefreshTimer();
    void        refreshVerify();
    void        startVerify(bool isRetry = false);
    void        stopVerifyAsync(bool release);
    void        releaseDeviceAsync();
    bool        stopVerify();
    bool        releaseDevice();
};
