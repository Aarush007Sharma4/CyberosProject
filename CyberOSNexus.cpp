/*
 * ============================================================
 *  CyberOS Nexus - C++ Console Simulation
 *  First Year B.Tech C++ Project
 * ============================================================
 *  Modules:
 *   1. Authentication System  (login, lockout, CAPTCHA, brute-force)
 *   2. Attack Lab             (brute force, phishing, DDoS, malware)
 *   3. Threat Intelligence    (threat score, radar pulses, timeline)
 *   4. Forensics Lab          (evidence analysis, FNV-1a hashing)
 *   5. Admin Panel            (quarantine, key rotation, host isolation)
 *   6. Command Console        (typed commands like a real analyst)
 *   7. Incident Report        (summary export to .txt file)
 * ============================================================
 *  Compile:  g++ -std=c++17 -o CyberOS_Nexus CyberOS_Nexus.cpp
 *  Run:      ./CyberOS_Nexus
 * ============================================================
 */

#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <sstream>
#include <ctime>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <algorithm>
#include <thread>
#include <chrono>
#include <cmath>

using namespace std;

// ─────────────────────────────────────────────
//  ANSI colour helpers  (Linux / macOS / WSL)
// ─────────────────────────────────────────────
#define RESET   "\033[0m"
#define GREEN   "\033[32m"
#define CYAN    "\033[36m"
#define YELLOW  "\033[33m"
#define RED     "\033[31m"
#define BLUE    "\033[34m"
#define BOLD    "\033[1m"
#define DIM     "\033[2m"

// ─────────────────────────────────────────────
//  Data structures
// ─────────────────────────────────────────────
struct Account {
    string   password;
    int      failCount   = 0;
    bool     locked      = false;
    bool     captcha     = false;
    int      cooldown    = 0;   // fake cooldown counter (seconds)
};

struct Event {
    string   type;   // "ok" | "warn" | "bad"
    string   time;
    string   title;
    string   message;
};

struct SystemState {
    int    totalRequests = 148;
    int    blockedIPs    = 6;
    int    threatScore   = 18;
    int    incidents     = 2;
    string systemMode    = "DEFENCE MODE";
    bool   attackPaused  = false;

    map<string, Account> accounts = {
        {"admin", {"admin123", 0, false, false, 0}},
        {"user1", {"pass1",    1, false, false, 0}},
        {"guest", {"guest",    0, false, false, 0}}
    };

    vector<Event> timeline = {
        {"warn", "08:14", "Suspicious login burst",
         "Repeated login attempts detected from multiple regions."},
        {"bad",  "08:21", "Attack vector escalated",
         "Simulation shifted into distributed attack pattern."},
        {"ok",   "08:29", "Defence layer responded",
         "Rate limiting and CAPTCHA controls remained active."}
    };
};

SystemState state;

// ─────────────────────────────────────────────
//  Utility helpers
// ─────────────────────────────────────────────
string currentTime() {
    time_t now = time(nullptr);
    tm*    t   = localtime(&now);
    char   buf[10];
    strftime(buf, sizeof(buf), "%H:%M:%S", t);
    return string(buf);
}

void pause(int ms = 300) {
    this_thread::sleep_for(chrono::milliseconds(ms));
}

void printSeparator(char ch = '-', int width = 60) {
    cout << DIM << string(width, ch) << RESET << "\n";
}

void printHeader(const string& title) {
    cout << "\n" << BOLD << GREEN;
    printSeparator('=');
    cout << "  " << title << "\n";
    printSeparator('=');
    cout << RESET;
}

void log(const string& msg, const string& colour = CYAN) {
    cout << colour << "root@cyberos:~$ " << RESET << msg << "\n";
    pause(60);
}

void addTimeline(const string& type, const string& title, const string& msg) {
    Event e;
    e.type    = type;
    e.time    = currentTime();
    e.title   = title;
    e.message = msg;
    state.timeline.insert(state.timeline.begin(), e);
    if (state.timeline.size() > 7)
        state.timeline.pop_back();
}

string threatColour() {
    if (state.threatScore < 25)  return GREEN;
    if (state.threatScore < 55)  return YELLOW;
    return RED;
}

string threatLabel() {
    if (state.threatScore < 25)  return "LOW";
    if (state.threatScore < 55)  return "MEDIUM";
    return "HIGH";
}

void printStatusBar() {
    cout << BOLD << CYAN
         << "\n[ CyberOS Nexus | "
         << currentTime()
         << " | Threat: " << threatColour() << threatLabel() << CYAN
         << " | Score: " << state.threatScore
         << " | Mode: " << YELLOW << state.systemMode << CYAN
         << " ]\n" << RESET;
}

// ─────────────────────────────────────────────
//  Module 1 : Authentication System
// ─────────────────────────────────────────────
void showAccountTable() {
    cout << "\n" << BOLD << CYAN
         << left << setw(12) << "User"
         << setw(14) << "Status"
         << setw(8)  << "Fails"
         << setw(12) << "Cooldown"
         << RESET << "\n";
    printSeparator();
    for (auto& [name, acc] : state.accounts) {
        string status = acc.locked   ? RED   "LOCKED"
                      : acc.captcha  ? YELLOW"CAPTCHA"
                                     : GREEN "OK";
        cout << left << setw(12) << name
             << status << RESET
             << setw(14 - (int)status.size() + 9 /* ansi escape len */) << " "
             << setw(8)  << acc.failCount
             << setw(12) << (acc.cooldown > 0 ? to_string(acc.cooldown)+"s" : "--")
             << "\n";
    }
}

void login() {
    printHeader("Authentication Portal");
    string username, password;
    cout << GREEN << "Username: " << RESET; cin >> username;
    cout << GREEN << "Password: " << RESET; cin >> password;

    if (state.accounts.find(username) == state.accounts.end()) {
        log("unknown user: " + username, RED);
        state.threatScore = min(100, state.threatScore + 2);
        return;
    }

    Account& acc = state.accounts[username];

    if (acc.locked) {
        log("account locked: " + username + " — admin intervention required", RED);
        return;
    }
    if (acc.captcha) {
        cout << YELLOW << "CAPTCHA: What is 7 + 5? " << RESET;
        int ans; cin >> ans;
        if (ans != 12) {
            log("CAPTCHA failed — access denied", RED);
            state.threatScore = min(100, state.threatScore + 3);
            return;
        }
        acc.captcha = false;
        log("CAPTCHA passed", GREEN);
    }

    if (acc.password == password) {
        acc.failCount = 0;
        log("authentication SUCCESS for user: " + username, GREEN);
        addTimeline("ok", "Successful login", "User '" + username + "' authenticated.");
        state.totalRequests++;
    } else {
        acc.failCount++;
        state.threatScore = min(100, state.threatScore + 4);
        state.totalRequests++;
        log("authentication FAILED for user: " + username
            + " (attempt " + to_string(acc.failCount) + ")", RED);

        if (acc.failCount >= 3 && !acc.locked) {
            acc.locked = true;
            state.blockedIPs++;
            state.incidents++;
            log("account LOCKED after 3 failures: " + username, RED);
            addTimeline("bad", "Account locked", "User '" + username + "' locked after brute-force.");
        } else if (acc.failCount == 2) {
            acc.captcha = true;
            log("CAPTCHA triggered for: " + username, YELLOW);
        }
    }
    showAccountTable();
}

void resetAuth() {
    for (auto& [name, acc] : state.accounts) {
        acc.failCount = 0;
        acc.captcha   = false;
        acc.cooldown  = 0;
        // Note: does NOT unlock — use admin panel for that
    }
    log("all login attempt counters reset", GREEN);
    addTimeline("ok", "Auth reset", "Attempt counters cleared.");
}

// ─────────────────────────────────────────────
//  Module 2 : Attack Lab
// ─────────────────────────────────────────────
void runAttack() {
    printHeader("Attack Laboratory");
    cout << GREEN << "Target (admin/user1/guest): " << RESET;
    string target; cin >> target;

    cout << GREEN << "Attack mode (brute/phish/ddos/malware): " << RESET;
    string mode; cin >> mode;

    if (state.accounts.find(target) == state.accounts.end()) {
        log("unknown target: " + target, RED);
        return;
    }

    if (mode == "brute") {
        log("initiating brute force on: " + target, RED);
        pause(400);
        for (int i = 1; i <= 3; i++) {
            log("attempt " + to_string(i) + ": password guess failed", RED);
            state.accounts[target].failCount++;
            state.threatScore = min(100, state.threatScore + 5);
            pause(300);
        }
        state.accounts[target].locked = true;
        state.blockedIPs++;
        state.incidents++;
        log("target LOCKED: brute force detected and blocked", YELLOW);
        addTimeline("bad", "Brute force blocked", "Target '" + target + "' locked after attack.");
    }
    else if (mode == "phish") {
        log("phishing vector dispatched to: " + target, YELLOW);
        state.threatScore = min(100, state.threatScore + 8);
        state.incidents++;
        log("phishing email simulation: 1 credential harvested (simulated)", RED);
        addTimeline("bad", "Phishing attempt", "Credential harvest simulation ran on '" + target + "'.");
    }
    else if (mode == "ddos") {
        log("DDoS flood initiated — 20,000 packets/sec (simulated)", RED);
        for (int i = 0; i < 4; i++) {
            pause(250);
            log("packet wave " + to_string(i+1) + " absorbed by rate limiter", YELLOW);
        }
        state.threatScore = min(100, state.threatScore + 12);
        state.blockedIPs += 3;
        log("DDoS mitigated — rate limiting active", GREEN);
        addTimeline("warn", "DDoS mitigated", "Flood packets absorbed by defence layer.");
    }
    else if (mode == "malware") {
        log("malware dropper payload injected into: " + target, RED);
        pause(500);
        log("quarantine triggered: payload isolated", YELLOW);
        state.threatScore = min(100, state.threatScore + 10);
        state.incidents++;
        log("secondary payload blocked — simulation complete", GREEN);
        addTimeline("bad", "Malware quarantined", "Payload isolated in simulation for '" + target + "'.");
    }
    else {
        log("unknown attack mode: " + mode, RED);
    }
    state.totalRequests += 5;
}

// ─────────────────────────────────────────────
//  Module 3 : Threat Intelligence
// ─────────────────────────────────────────────
void showRadar() {
    printHeader("Threat Intelligence Radar");
    cout << "\n";
    // Print a simple ASCII radar grid
    const int SIZE = 21;
    vector<string> grid(SIZE, string(SIZE * 2 + 1, '.'));

    // Draw concentric rings (rough ASCII circles)
    auto drawCircle = [&](int cx, int cy, int r, char ch) {
        for (int y = 0; y < SIZE; y++)
            for (int x = 0; x < SIZE; x++) {
                int dx = x - cx, dy = y - cy;
                float dist = sqrt(dx*dx + dy*dy);
                if (dist >= r - 0.6f && dist <= r + 0.6f)
                    grid[y][x * 2] = ch;
            }
    };

    drawCircle(SIZE/2, SIZE/2, 4,  'o');
    drawCircle(SIZE/2, SIZE/2, 8,  'o');
    drawCircle(SIZE/2, SIZE/2, 10, 'o');

    // Seed a few random threat nodes
    srand((unsigned)time(nullptr));
    int numNodes = 3 + rand() % 5;
    for (int i = 0; i < numNodes; i++) {
        int x = 2 + rand() % (SIZE - 4);
        int y = 2 + rand() % (SIZE - 4);
        char sym = (rand() % 3 == 0) ? 'X' : (rand() % 2 == 0) ? '!' : '*';
        grid[y][x * 2] = sym;
    }

    // Centre marker
    grid[SIZE/2][SIZE] = '+';

    // Print with colours
    for (auto& row : grid) {
        for (char ch : row) {
            if      (ch == 'X') cout << RED    << ch << RESET;
            else if (ch == '!') cout << YELLOW << ch << RESET;
            else if (ch == '*') cout << CYAN   << ch << RESET;
            else if (ch == '+') cout << GREEN  << ch << RESET;
            else if (ch == 'o') cout << DIM    << ch << RESET;
            else                cout << ch;
        }
        cout << "\n";
    }
    cout << "\n";
    cout << GREEN << "  [+] " << RESET << "Centre node     "
         << RED   << "  [X] " << RESET << "High-risk IP    "
         << YELLOW<< "  [!] " << RESET << "Suspicious      "
         << CYAN  << "  [*] " << RESET << "Monitored\n";

    log("threat radar scan complete — " + to_string(numNodes) + " nodes detected", CYAN);
    state.totalRequests += 2;
}

void showTimeline() {
    printHeader("Event Timeline");
    for (auto& ev : state.timeline) {
        string col = (ev.type == "bad")  ? RED
                   : (ev.type == "warn") ? YELLOW
                                         : GREEN;
        cout << col << "  [" << ev.time << "] " << BOLD << ev.title << RESET << "\n"
             << "          " << ev.message << "\n\n";
    }
}

// ─────────────────────────────────────────────
//  Module 4 : Forensics Lab
// ─────────────────────────────────────────────
// FNV-1a 32-bit hash — same algorithm used in the HTML project
uint32_t fnv1aHash(const string& s) {
    uint32_t hash = 2166136261u;
    for (unsigned char c : s) {
        hash ^= c;
        hash *= 16777619u;
    }
    return hash;
}

void analyzeEvidence() {
    printHeader("Forensics Lab");
    cout << GREEN << "Enter evidence artifact (e.g. 'admin token leaked'): " << RESET;
    cin.ignore();
    string evidence; getline(cin, evidence);

    if (evidence.empty()) {
        log("no evidence provided", YELLOW);
        return;
    }

    // Risk scoring — keyword matching
    string risk;
    string col;
    vector<string> highKeywords  = {"token","password","admin","ip","leak","phish","malware","shell"};
    vector<string> medKeywords   = {"log","packet","hash","trace"};

    auto containsAny = [&](const vector<string>& kws) {
        string low = evidence;
        transform(low.begin(), low.end(), low.begin(), ::tolower);
        for (auto& kw : kws)
            if (low.find(kw) != string::npos) return true;
        return false;
    };

    if      (containsAny(highKeywords)) { risk = "HIGH";   col = RED;    }
    else if (containsAny(medKeywords))  { risk = "MEDIUM"; col = YELLOW; }
    else                                { risk = "LOW";    col = GREEN;  }

    log("artifact analysed: " + evidence, CYAN);
    log("suspicion level: " + risk, col);

    // Compute hash fingerprint
    uint32_t hash = fnv1aHash(evidence);
    ostringstream oss;
    oss << hex << setw(8) << setfill('0') << hash;
    log("FNV-1a fingerprint: 0x" + oss.str(), GREEN);

    state.threatScore += (risk == "HIGH") ? 7 : (risk == "MEDIUM") ? 3 : 1;
    state.threatScore  = min(100, state.threatScore);
    addTimeline(risk == "HIGH" ? "bad" : risk == "MEDIUM" ? "warn" : "ok",
                "Evidence analysed",
                "Artifact classified as " + risk + ".");
}

void sealEvidence() {
    log("evidence sealed and locked in digital vault", CYAN);
    log("chain of custody: " + currentTime() + " — preserved", GREEN);
    addTimeline("ok", "Evidence sealed", "Chain of custody preserved.");
}

// ─────────────────────────────────────────────
//  Module 5 : Admin Panel
// ─────────────────────────────────────────────
void unlockAll() {
    for (auto& [name, acc] : state.accounts) {
        acc.locked = acc.captcha = false;
        acc.cooldown = 0;
    }
    state.systemMode = "DEFENCE MODE";
    state.threatScore = max(8, state.threatScore - 8);
    log("all accounts unlocked — defence mode restored", GREEN);
    addTimeline("ok", "Accounts unlocked", "Administrator restored access to all users.");
}

void quarantineNetwork() {
    state.systemMode = "QUARANTINE";
    state.threatScore = min(100, state.threatScore + 12);
    state.blockedIPs += 2;
    log("network quarantined — all new sessions restricted", RED);
    addTimeline("bad", "Network quarantined", "High-risk mode enabled across the mesh.");
}

void rotateKeys() {
    state.totalRequests++;
    log("encryption keys rotated — session keys refreshed", CYAN);
    addTimeline("ok", "Key rotation completed", "Session keys refreshed.");
}

void isolateHost() {
    string hostname;
    cout << GREEN << "Enter hostname to isolate: " << RESET;
    cin >> hostname;
    state.blockedIPs++;
    state.threatScore = min(100, state.threatScore + 5);
    log("host isolated: " + hostname, YELLOW);
    addTimeline("warn", "Host isolated", "Endpoint '" + hostname + "' removed from mesh.");
}

void clearAlerts() {
    state.timeline.erase(
        remove_if(state.timeline.begin(), state.timeline.end(),
                  [](const Event& ev){ return ev.type == "bad" || ev.type == "warn"; }),
        state.timeline.end());
    log("threat alerts cleared — timeline cleaned", GREEN);
}

void restoreDefaults() {
    state.totalRequests = 148;
    state.blockedIPs    = 6;
    state.threatScore   = 18;
    state.incidents     = 2;
    state.systemMode    = "DEFENCE MODE";
    state.accounts = {
        {"admin", {"admin123", 0, false, false, 0}},
        {"user1", {"pass1",    1, false, false, 0}},
        {"guest", {"guest",    0, false, false, 0}}
    };
    state.timeline = {
        {"warn", "08:14", "Suspicious login burst",
         "Repeated login attempts detected from multiple regions."},
        {"bad",  "08:21", "Attack vector escalated",
         "Simulation shifted into distributed attack pattern."},
        {"ok",   "08:29", "Defence layer responded",
         "Rate limiting and CAPTCHA controls remained active."}
    };
    log("system restored to default baseline", GREEN);
}

// ─────────────────────────────────────────────
//  Module 6 : Command Console
// ─────────────────────────────────────────────
void runConsoleCommand(const string& cmd) {
    if      (cmd == "help")
        cout << GREEN << "commands: help, status, scan, lockdown, report, clear, "
                         "ping, unlock, export, quit\n" << RESET;
    else if (cmd == "status")
        cout << GREEN << "requests=" << state.totalRequests
             << "  blocked=" << state.blockedIPs
             << "  threat="  << state.threatScore
             << "  mode="    << state.systemMode << "\n" << RESET;
    else if (cmd == "scan") {
        log("deep scan complete: suspicious traces found in auth layer", YELLOW);
        state.threatScore = min(100, state.threatScore + 2);
    }
    else if (cmd == "lockdown")  quarantineNetwork();
    else if (cmd == "unlock")    unlockAll();
    else if (cmd == "ping")      log("pong from security mesh node 7", CYAN);
    else if (cmd == "clear")     cout << "\033[2J\033[H";
    else if (cmd == "export") {
        // Handled by report module below
        log("use the Incident Report menu to export the full report", CYAN);
    }
    else if (cmd == "quit" || cmd == "exit")
        exit(0);
    else
        log("unknown command. type 'help'.", RED);
}

void commandConsole() {
    printHeader("Command Console");
    cout << DIM << "Type commands below. Type 'back' to return to main menu.\n" << RESET;
    log("console ready — type 'help' for command list", GREEN);
    cin.ignore();
    while (true) {
        cout << CYAN << "cyberos> " << RESET;
        string cmd; getline(cin, cmd);
        if (cmd == "back") break;
        runConsoleCommand(cmd);
    }
}

// ─────────────────────────────────────────────
//  Module 7 : Incident Report  +  Export
// ─────────────────────────────────────────────
void printReport() {
    printHeader("Incident Report");
    cout << BOLD << "  Time        : " << RESET << currentTime()             << "\n"
         << BOLD << "  Total Req   : " << RESET << state.totalRequests       << "\n"
         << BOLD << "  Blocked IPs : " << RESET << state.blockedIPs          << "\n"
         << BOLD << "  Threat Score: " << RESET << threatColour() << state.threatScore << RESET << "\n"
         << BOLD << "  Incidents   : " << RESET << state.incidents            << "\n"
         << BOLD << "  System Mode : " << RESET << YELLOW << state.systemMode << RESET << "\n\n";

    showTimeline();

    // AI-style verdict
    string verdict;
    if      (state.threatScore < 25) verdict = "The defence stack is stable and disciplined.";
    else if (state.threatScore < 55) verdict = "The system is reacting well, but activity is rising.";
    else                             verdict = "Containment is still working, but the incident is becoming serious.";
    cout << threatColour() << BOLD << "  AI Verdict: " << RESET << verdict << "\n";
}

void exportReport() {
    string filename = "cyberos_nexus_report.txt";
    ofstream out(filename);
    if (!out.is_open()) {
        log("export failed — could not open file", RED);
        return;
    }
    out << "CyberOS Nexus Incident Report\n";
    out << "Time            : " << currentTime()       << "\n";
    out << "Total Requests  : " << state.totalRequests  << "\n";
    out << "Blocked IPs     : " << state.blockedIPs     << "\n";
    out << "Threat Score    : " << state.threatScore    << "\n";
    out << "Active Incidents: " << state.incidents      << "\n";
    out << "System Mode     : " << state.systemMode     << "\n\n";
    out << "Timeline:\n";
    for (auto& ev : state.timeline)
        out << "  [" << ev.time << "] " << ev.title << " — " << ev.message << "\n";

    string verdict;
    if      (state.threatScore < 25) verdict = "Stable.";
    else if (state.threatScore < 55) verdict = "Moderate activity. Monitoring required.";
    else                             verdict = "High risk. Containment ongoing.";
    out << "\nAI Verdict: " << verdict << "\n";
    out.close();
    log("report exported to: " + filename, GREEN);
}

// ─────────────────────────────────────────────
//  Dashboard summary
// ─────────────────────────────────────────────
void showDashboard() {
    printHeader("CyberOS Nexus — Dashboard");
    printStatusBar();

    cout << "\n"
         << GREEN  << "  Total Requests  : " << RESET << BOLD << state.totalRequests << RESET << "\n"
         << RED    << "  Blocked IPs     : " << RESET << BOLD << state.blockedIPs    << RESET << "\n"
         << YELLOW << "  Threat Score    : " << RESET << BOLD << state.threatScore   << RESET << "\n"
         << CYAN   << "  Active Incidents: " << RESET << BOLD << state.incidents     << RESET << "\n";

    // ASCII threat bar
    int bar = state.threatScore / 5;
    cout << "\n  Threat Pressure  [";
    for (int i = 0; i < 20; i++)
        cout << (i < bar ? (i < 5 ? "=" : i < 11 ? "=" : "=") : " ");
    cout << "] " << threatColour() << state.threatScore << "%" << RESET << "\n";

    cout << "\n  Defence Stack:\n"
         << GREEN  << "    [✓] Rate Limiting     ACTIVE\n"
         << "    [✓] CAPTCHA Filter    ACTIVE\n"
         << "    [✓] Account Lockout   ACTIVE\n"
         << YELLOW << "    [~] AI Verdict Engine  " << threatLabel() << "\n" << RESET;
}

// ─────────────────────────────────────────────
//  Main menu
// ─────────────────────────────────────────────
void mainMenu() {
    while (true) {
        printStatusBar();
        cout << "\n"
             << GREEN << "  ╔══════════════════════════════════╗\n"
             << "  ║       CyberOS Nexus — Menu       ║\n"
             << "  ╚══════════════════════════════════╝\n" << RESET
             << "\n"
             << "  1.  Dashboard\n"
             << "  2.  Authentication Portal\n"
             << "  3.  Attack Lab\n"
             << "  4.  Threat Intelligence Radar\n"
             << "  5.  Forensics Lab\n"
             << "  6.  Command Console\n"
             << "  7.  Admin Panel\n"
             << "  8.  Incident Report\n"
             << "  9.  Export Report (.txt)\n"
             << "  0.  Quit\n\n"
             << CYAN << "  cyberos> " << RESET;

        int choice;
        cin >> choice;

        switch (choice) {
            case 1: showDashboard();  break;
            case 2: login();          break;
            case 3: runAttack();      break;
            case 4:
                showRadar();
                showTimeline();
                break;
            case 5:
                analyzeEvidence();
                sealEvidence();
                break;
            case 6: commandConsole(); break;
            case 7: {
                printHeader("Admin Panel");
                cout << "  1. Unlock all accounts\n"
                     << "  2. Quarantine network\n"
                     << "  3. Rotate encryption keys\n"
                     << "  4. Isolate host\n"
                     << "  5. Clear threat alerts\n"
                     << "  6. Restore defaults\n"
                     << CYAN << "  admin> " << RESET;
                int ac; cin >> ac;
                if      (ac == 1) unlockAll();
                else if (ac == 2) quarantineNetwork();
                else if (ac == 3) rotateKeys();
                else if (ac == 4) isolateHost();
                else if (ac == 5) clearAlerts();
                else if (ac == 6) restoreDefaults();
                else              log("invalid option", RED);
                break;
            }
            case 8: printReport();  break;
            case 9: exportReport(); break;
            case 0:
                log("shutting down CyberOS Nexus... goodbye.", GREEN);
                return;
            default:
                log("invalid option. try again.", RED);
        }
    }
}

// ─────────────────────────────────────────────
//  Boot sequence
// ─────────────────────────────────────────────
void bootSequence() {
    system("clear");
    cout << GREEN << BOLD << R"(
   ______      __              ____  _____   _   __
  / ____/_  __/ /_  ___  _____/ __ \/ ___/  / | / /__  _  ____  _______
 / /   / / / / __ \/ _ \/ ___/ / / /\__ \  /  |/ / _ \| |/_/ / / / ___/
/ /___/ /_/ / /_/ /  __/ /  / /_/ /___/ / / /|  /  __/>  </ /_/ (__  )
\____/\__, /_.___/\___/_/   \____//____/ /_/ |_/\___/_/|_|\__,_/____/
     /____/
)" << RESET;

    cout << DIM << "  A futuristic cyber defence lab — First Year B.Tech C++ Project\n\n" << RESET;
    pause(500);

    vector<string> bootLines = {
        "kernel: CyberOS v2.4.1 initialised",
        "auth: loading account table",
        "net:  binding to interface eth0",
        "ai:   threat model loaded",
        "ids:  intrusion detection active",
        "log:  event logger online",
        "boot: all systems nominal"
    };
    for (auto& line : bootLines) {
        log(line, CYAN);
        pause(200);
    }
    log("CyberOS Nexus ready.", GREEN);
    pause(400);
}

// ─────────────────────────────────────────────
//  Entry point
// ─────────────────────────────────────────────
int main() {
    bootSequence();
    mainMenu();
    return 0;
}
