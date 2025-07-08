#include <iostream>
#include <string>
#include <vector>
#include <limits>
#include <chrono>
#include <thread>
#include <mutex>
#include <fstream>
#include <sstream>
#include <regex>
#include <algorithm>
using namespace std;

// Simulate bcrypt with a simple hash (in practice, use a real hashing library)
string hashPassword(const string& password) {
    string hashed;
    for (char c : password) {
        hashed += to_string((int)c * 31 % 256); // Simple hash for demo
    }
    return hashed;
}

// Simulate file encryption with XOR (in practice, use OpenSSL or similar)
string xorEncryptDecrypt(const string& data, char key = 'K') {
    string result = data;
    for (char& c : result) {
        c ^= key;
    }
    return result;
}

enum Role { CUSTOMER, EMPLOYEE, ADMIN };
enum Permission { CAN_WITHDRAW, CAN_DEPOSIT, CAN_TRANSFER, CAN_CHECK_BALANCE, CAN_VIEW_HISTORY, CAN_ADJUST_BALANCE, CAN_VIEW_ALL_TRANSACTIONS };

class BankAccount {
public:
    string name;
    string userName;
    string password; // Stores hashed password
    string accountNo;
    float balance = 100000.0f;
    int transactions = 0;
    string transactionHistory = "";
    Role role = CUSTOMER;
    vector<Permission> permissions;
    int failedLoginAttempts = 0;
    bool accountLocked = false;
    mutex accountMutex; // Per-account mutex
    static string globalTransactionHistory;
    static mutex globalMutex; // Mutex for global transaction history

    // Delete copy constructor and copy assignment
    BankAccount(const BankAccount&) = delete;
    BankAccount& operator=(const BankAccount&) = delete;

    // Move constructor
    BankAccount(BankAccount&& other) noexcept
        : name(move(other.name)),
        userName(move(other.userName)),
        password(move(other.password)),
        accountNo(move(other.accountNo)),
        balance(other.balance),
        transactions(other.transactions),
        transactionHistory(move(other.transactionHistory)),
        role(other.role),
        permissions(move(other.permissions)),
        failedLoginAttempts(other.failedLoginAttempts),
        accountLocked(other.accountLocked) {
        // mutex is not movable, but we don't need to move it (new mutex is fine)
    }

    // Move assignment operator
    BankAccount& operator=(BankAccount&& other) noexcept {
        if (this != &other) {
            name = move(other.name);
            userName = move(other.userName);
            password = move(other.password);
            accountNo = move(other.accountNo);
            balance = other.balance;
            transactions = other.transactions;
            transactionHistory = move(other.transactionHistory);
            role = other.role;
            permissions = move(other.permissions);
            failedLoginAttempts = other.failedLoginAttempts;
            accountLocked = other.accountLocked;
        }
        return *this;
    }

    // Default constructor
    BankAccount() = default;

    void assignPermissions() {
        permissions = { CAN_WITHDRAW, CAN_DEPOSIT, CAN_TRANSFER, CAN_CHECK_BALANCE, CAN_VIEW_HISTORY };
        if (role == EMPLOYEE || role == ADMIN) {
            permissions.push_back(CAN_ADJUST_BALANCE);
        }
        if (role == ADMIN) {
            permissions.push_back(CAN_VIEW_ALL_TRANSACTIONS);
        }
    }

    bool hasPermission(Permission p) {
        return find(permissions.begin(), permissions.end(), p) != permissions.end();
    }

    void registerAccount() {
        // Input sanitization
        regex validInput("^[a-zA-Z0-9]{3,20}$"); // Alphanumeric, 3-20 chars
        cout << "\nEnter Your Name (3-20 alphanumeric chars) - ";
        getline(cin, name);
        if (!regex_match(name, validInput)) {
            cout << "\nInvalid name format!" << endl;
            name = "";
            return;
        }

        cout << "\nEnter Your Username (3-20 alphanumeric chars) - ";
        getline(cin, userName);
        if (!regex_match(userName, validInput)) {
            cout << "\nInvalid username format!" << endl;
            userName = "";
            return;
        }

        cout << "\nEnter Your Password (3-20 alphanumeric chars) - ";
        getline(cin, password);
        if (!regex_match(password, validInput)) {
            cout << "\nInvalid password format!" << endl;
            password = "";
            return;
        }
        password = hashPassword(password); // Hash password

        cout << "\nEnter Your Account Number (3-20 alphanumeric chars) - ";
        getline(cin, accountNo);
        if (!regex_match(accountNo, validInput)) {
            cout << "\nInvalid account number format!" << endl;
            accountNo = "";
            return;
        }

        cout << "\nSelect Role (1. Customer, 2. Employee, 3. Admin): ";
        int r;
        if (!(cin >> r)) {
            cout << "\nInvalid role input!" << endl;
            cin.clear();
            cin.ignore(10000, '\n');
            return;
        }
        cin.ignore(10000, '\n');
        if (r == 2 || r == 3) {
            string secretCode;
            cout << "\nEnter secret code for elevated role: ";
            getline(cin, secretCode);
            if (secretCode != "SECRET123") { // Simulate admin verification
                cout << "\nInvalid secret code. Registered as Customer." << endl;
                role = CUSTOMER;
            }
            else {
                role = (r == 2) ? EMPLOYEE : ADMIN;
            }
        }
        else {
            role = CUSTOMER;
        }

        assignPermissions();
        cout << "\nRegistration completed.. kindly login" << endl;
    }

    bool login(const string& inputUser, const string& inputPass) {
        if (accountLocked) {
            cout << "\nAccount is locked due to too many failed attempts." << endl;
            return false;
        }
        bool success = (inputUser == userName && hashPassword(inputPass) == password);
        if (!success) {
            failedLoginAttempts++;
            if (failedLoginAttempts >= 3) {
                accountLocked = true;
                cout << "\nToo many failed attempts. Account locked." << endl;
            }
        }
        else {
            failedLoginAttempts = 0; // Reset on successful login
        }
        return success;
    }

    void withdraw() {
        if (!hasPermission(CAN_WITHDRAW)) {
            cout << "\nPermission denied." << endl;
            return;
        }
        float amount;
        cout << "\nEnter amount to withdraw - ";
        if (!(cin >> amount)) {
            cout << "\nInvalid amount!" << endl;
            cin.clear();
            cin.ignore(10000, '\n');
            return;
        }
        cin.ignore(10000, '\n');
        lock_guard<mutex> lock(accountMutex);
        if (balance >= amount) {
            transactions++;
            balance -= amount;
            cout << "\nWithdraw Successfully" << endl;
            string transaction = to_string(amount) + " LE Withdrawed by " + userName + "\n";
            transactionHistory += transaction;
            {
                lock_guard<mutex> globalLock(globalMutex);
                globalTransactionHistory += transaction;
            }
        }
        else {
            cout << "\nInsufficient Balance" << endl;
        }
    }

    void deposit() {
        if (!hasPermission(CAN_DEPOSIT)) {
            cout << "\nPermission denied." << endl;
            return;
        }
        float amount;
        cout << "\nEnter amount to deposit - ";
        if (!(cin >> amount)) {
            cout << "\nInvalid amount!" << endl;
            cin.clear();
            cin.ignore(10000, '\n');
            return;
        }
        cin.ignore(10000, '\n');
        lock_guard<mutex> lock(accountMutex);
        if (amount <= 100000.0f) {
            transactions++;
            balance += amount;
            cout << "\nSuccessfully Deposited" << endl;
            string transaction = to_string(amount) + " LE deposited by " + userName + "\n";
            transactionHistory += transaction;
            {
                lock_guard<mutex> globalLock(globalMutex);
                globalTransactionHistory += transaction;
            }
        }
        else {
            cout << "\nSorry...Limit is 100000.00" << endl;
        }
    }

    void transfer(vector<BankAccount>& accounts) {
        if (!hasPermission(CAN_TRANSFER)) {
            cout << "\nPermission denied." << endl;
            return;
        }
        string recipientUser;
        float amount;
        cout << "\nEnter Recipient's Username - ";
        cin.ignore(10000, '\n');
        getline(cin, recipientUser);
        cout << "\nEnter amount to transfer - ";
        if (!(cin >> amount)) {
            cout << "\nInvalid amount!" << endl;
            cin.clear();
            cin.ignore(10000, '\n');
            return;
        }
        cin.ignore(10000, '\n');

        BankAccount* recipient = nullptr;
        for (auto& acc : accounts) {
            if (acc.userName == recipientUser) {
                recipient = &acc;
                break;
            }
        }

        if (recipient == nullptr) {
            cout << "\nRecipient not found." << endl;
            return;
        }

        // Lock accounts in consistent order to prevent deadlock
        mutex* firstLock = &accountMutex;
        mutex* secondLock = &recipient->accountMutex;
        if (userName > recipient->userName) {
            swap(firstLock, secondLock);
        }
        lock_guard<mutex> lock1(*firstLock);
        lock_guard<mutex> lock2(*secondLock);

        if (balance >= amount) {
            if (amount <= 50000.0f) {
                transactions++;
                balance -= amount;
                recipient->balance += amount;
                recipient->transactions++;
                cout << "\nSuccessfully Transferred to " << recipient->name << endl;
                string transaction = to_string(amount) + " LE transferred from " + userName + " to " + recipient->userName + "\n";
                transactionHistory += to_string(amount) + " LE transferred to " + recipient->userName + "\n";
                recipient->transactionHistory += to_string(amount) + " LE received from " + userName + "\n";
                {
                    lock_guard<mutex> globalLock(globalMutex);
                    globalTransactionHistory += transaction;
                }
            }
            else {
                cout << "\nSorry...Limit is 50000.00" << endl;
            }
        }
        else {
            cout << "\nInsufficient Balance" << endl;
        }
    }

    void checkBalance() {
        if (!hasPermission(CAN_CHECK_BALANCE)) {
            cout << "\nPermission denied." << endl;
            return;
        }
        lock_guard<mutex> lock(accountMutex);
        cout << "\n" << balance << " LE" << endl;
    }

    void transHistory() {
        if (!hasPermission(CAN_VIEW_HISTORY)) {
            cout << "\nPermission denied." << endl;
            return;
        }
        lock_guard<mutex> lock(accountMutex);
        if (transactions == 0) {
            cout << "\nEmpty" << endl;
        }
        else {
            cout << "\n" << transactionHistory << endl;
        }
    }

    void viewAllTransactions() {
        if (!hasPermission(CAN_VIEW_ALL_TRANSACTIONS)) {
            cout << "\nAccess Denied. Only Admin can view all transactions." << endl;
            return;
        }
        lock_guard<mutex> globalLock(globalMutex);
        string auditLog = "Admin " + userName + " viewed all transactions\n";
        globalTransactionHistory += auditLog;
        if (globalTransactionHistory.empty()) {
            cout << "\nNo transactions have occurred." << endl;
        }
        else {
            cout << "\nGlobal Transaction History:\n" << globalTransactionHistory << endl;
        }
    }

    void adjustBalance(vector<BankAccount>& accounts) {
        if (!hasPermission(CAN_ADJUST_BALANCE)) {
            cout << "\nAccess Denied. Only Admin can adjust balances." << endl;
            return;
        }
        string targetUser;
        cout << "\nEnter the username of the customer to adjust balance: ";
        cin.ignore(10000, '\n');
        getline(cin, targetUser);

        BankAccount* targetAccount = nullptr;
        for (auto& acc : accounts) {
            if (acc.userName == targetUser) {
                targetAccount = &acc;
                break;
            }
        }

        if (targetAccount == nullptr) {
            cout << "\nCustomer not found!" << endl;
            return;
        }

        float newBal;
        cout << "\nEnter new balance for " << targetAccount->name << " (" << targetAccount->userName << "): ";
        if (!(cin >> newBal)) {
            cout << "\nInvalid balance!" << endl;
            cin.clear();
            cin.ignore(10000, '\n');
            return;
        }
        cin.ignore(10000, '\n');

        lock_guard<mutex> lock(targetAccount->accountMutex);
        targetAccount->balance = newBal;
        string transaction = "Balance adjusted to " + to_string(newBal) + " LE for " + targetAccount->userName + " by Admin " + userName + "\n";
        targetAccount->transactionHistory += transaction;
        {
            lock_guard<mutex> globalLock(globalMutex);
            globalTransactionHistory += transaction;
        }
        cout << "\nBalance for " << targetAccount->name << " has been adjusted to: " << targetAccount->balance << endl;
    }

    string toString() const {
        stringstream ss;
        ss << xorEncryptDecrypt(name) << '\n' << xorEncryptDecrypt(userName) << '\n' << xorEncryptDecrypt(password) << '\n';
        ss << xorEncryptDecrypt(accountNo) << '\n' << balance << '\n' << transactions << '\n';
        ss << xorEncryptDecrypt(transactionHistory) << '\n' << role << '\n' << failedLoginAttempts << '\n' << accountLocked << '\n';
        return ss.str();
    }

    void fromString(ifstream& file) {
        // Robust file reading with error handling
        string line;
        if (!getline(file, line)) return; name = xorEncryptDecrypt(line);
        if (!getline(file, line)) return; userName = xorEncryptDecrypt(line);
        if (!getline(file, line)) return; password = xorEncryptDecrypt(line);
        if (!getline(file, line)) return; accountNo = xorEncryptDecrypt(line);
        if (!(file >> balance >> transactions)) return;
        file.ignore(10000, '\n');
        if (!getline(file, line)) return; transactionHistory = xorEncryptDecrypt(line);
        int r;
        if (!(file >> r)) return; role = static_cast<Role>(r);
        if (!(file >> failedLoginAttempts >> accountLocked)) return;
        file.ignore(10000, '\n');
        assignPermissions();
    }
};

// Initialize static members
string BankAccount::globalTransactionHistory = "";
mutex BankAccount::globalMutex;

void saveAllAccounts(const vector<BankAccount>& accounts) {
    ofstream file("accounts.txt");
    if (!file.is_open()) {
        cout << "\nError: Could not open accounts.txt for writing!" << endl;
        return;
    }
    for (const auto& acc : accounts) {
        file << acc.toString();
    }
    file.close();

    ofstream globalFile("global_transactions.txt");
    if (!globalFile.is_open()) {
        cout << "\nError: Could not open global_transactions.txt for writing!" << endl;
        return;
    }
    globalFile << xorEncryptDecrypt(BankAccount::globalTransactionHistory);
    globalFile.close();
}

vector<BankAccount> loadAllAccounts() {
    vector<BankAccount> accounts;
    ifstream file("accounts.txt");
    if (!file.is_open()) {
        cout << "\nWarning: Could not open accounts.txt. Starting with empty accounts." << endl;
        return accounts;
    }
    while (file.peek() != EOF) {
        BankAccount acc;
        acc.fromString(file);
        if (!acc.userName.empty()) { // Only add valid accounts
            accounts.emplace_back(move(acc)); // Use emplace_back to avoid copying
        }
    }
    file.close();

    ifstream globalFile("global_transactions.txt");
    if (!globalFile.is_open()) {
        cout << "\nWarning: Could not open global_transactions.txt." << endl;
    }
    else {
        string line;
        BankAccount::globalTransactionHistory = "";
        while (getline(globalFile, line)) {
            BankAccount::globalTransactionHistory += xorEncryptDecrypt(line) + "\n";
        }
        globalFile.close();
    }
    return accounts;
}

int takeIntegerInput(int limit) {
    int input;
    while (true) {
        cout << "\nEnter your choice: ";
        if (cin >> input && input >= 0 && input <= limit)
            return input;
        else {
            cout << "Invalid input. Try again.\n";
            cin.clear();
            cin.ignore(10000, '\n');
        }
    }
}

bool isSessionTimedOut(chrono::steady_clock::time_point startTime) {
    auto now = chrono::steady_clock::now();
    auto duration = chrono::duration_cast<chrono::minutes>(now - startTime);
    return duration.count() >= 5; // Timeout after 5 minutes
}



// Add these two functions to handle loading and saving login data

void saveLoginData(const vector<BankAccount>& accounts) {
    // Saving all accounts data to a file for persistence across sessions
    ofstream file("accounts.txt");
    if (!file.is_open()) {
        cout << "\nError: Could not open accounts.txt for writing!" << endl;
        return;
    }
    for (const auto& acc : accounts) {
        file << acc.toString();
    }
    file.close();
}

vector<BankAccount> loadLoginData() {
    vector<BankAccount> accounts;
    ifstream file("accounts.txt");
    if (!file.is_open()) {
        cout << "\nWarning: Could not open accounts.txt. Starting with empty accounts." << endl;
        return accounts;
    }
    while (file.peek() != EOF) {
        BankAccount acc;
        acc.fromString(file);
        if (!acc.userName.empty()) { // Only add valid accounts
            accounts.emplace_back(move(acc)); // Use emplace_back to avoid copying
        }
    }
    file.close();
    return accounts;
}

int main() {
    cout << "\n*WELCOME TO SECURE ATM SYSTEM*\n" << endl;

    // Load account data from file at the beginning of the program
    vector<BankAccount> accounts = loadLoginData();

    while (true) {
        cout << "1. Login\n2. Register New Account\n3. Exit" << endl;
        int choice = takeIntegerInput(3);
        cin.ignore(10000, '\n');

        if (choice == 1) {
            string user, pass;
            cout << "\nEnter Your Username - ";
            getline(cin, user);
            cout << "\nEnter Your Password - ";
            getline(cin, pass);
            bool found = false;

            for (auto& acc : accounts) {
                if (acc.login(user, pass)) {
                    cout << "\nLogin successful!! Welcome " << acc.name << endl;
                    found = true;

                    auto sessionStart = chrono::steady_clock::now();
                    bool isFinished = false;
                    while (!isFinished) {
                        if (isSessionTimedOut(sessionStart)) {
                            cout << "\nSession timed out. Logging out." << endl;
                            isFinished = true;
                            break;
                        }

                        cout << "\n1. Withdraw\n2. Deposit\n3. Transfer\n4. Check Balance\n5. Transaction History";
                        if (acc.role == ADMIN) {
                            cout << "\n6. Adjust Balance\n7. View All Transactions";
                        }
                        cout << "\n0. Logout";

                        int limit = (acc.role == ADMIN) ? 7 : 5;
                        int action = takeIntegerInput(limit);
                        sessionStart = chrono::steady_clock::now(); // Reset timer on action
                        switch (action) {
                        case 1: acc.withdraw(); break;
                        case 2: acc.deposit(); break;
                        case 3: acc.transfer(accounts); break;
                        case 4: acc.checkBalance(); break;
                        case 5: acc.transHistory(); break;
                        case 6:
                            if (acc.role == ADMIN) acc.adjustBalance(accounts);
                            break;
                        case 7:
                            if (acc.role == ADMIN) acc.viewAllTransactions();
                            break;
                        case 0:
                            isFinished = true;
                            break;
                        }
                        saveLoginData(accounts);  // Save data after every action
                    }
                    break;
                }
            }

            if (!found) cout << "\nLogin failed. Please try again." << endl;

        }
        else if (choice == 2) {
            BankAccount newAcc;
            newAcc.registerAccount();
            if (!newAcc.userName.empty()) { // Only add if registration is valid
                accounts.emplace_back(move(newAcc)); // Use emplace_back to avoid copying
                saveLoginData(accounts);  // Save data after registering a new account
            }
        }
        else {
            break;
        }
    }

    cout << "\nThank you for using our ATM System.\n";
    return 0;
}
