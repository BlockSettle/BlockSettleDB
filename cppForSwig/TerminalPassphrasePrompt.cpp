////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 20119, goatpig.                                             //
//  Distributed under the MIT license                                         //
//  See LICENSE-MIT or https://opensource.org/licenses/MIT                    //                                      
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "TerminalPassphrasePrompt.h"

#ifdef WIN32
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

using namespace std;
    
////////////////////////////////////////////////////////////////////////////////
SecureBinaryData TerminalPassphrasePrompt::prompt(const set<BinaryData>& idSet)
{
    unique_lock<mutex> lock(mu_);

    //check ids
    if (idSet.size() == 0)
    {
        //empty ids means we need to prompt for a new passphrase
        cout << endl;
        cout << "Set password for " << verbose_ << endl;

        return promptNewPass();
    }
    else if (idSet.size() == 1)
    {
        auto iter = idSet.find(CHANGE_PASS_FLAG);
        if (iter != idSet.end())
        {
            cout << "Changing password for " << verbose_ << endl;
            return promptNewPass();
        }
    }

    //we have ids, prompt the user for it
    return promptForPassphrase(idSet);
}

////////////////////////////////////////////////////////////////////////////////
SecureBinaryData TerminalPassphrasePrompt::promptNewPass()
{   
    while (true)
    {
        string pass1, pass2;
        cout << "Enter new password: ";

        setEcho(false);
        cin >> pass1;
        setEcho(true);
        cout << endl;

        cout << "Repeat new password: ";

        setEcho(false);
        cin >> pass2;
        setEcho(true);
        cout << endl;

        if (pass1 != pass2)
        {
            cout << "Password mismatch, try again!" << endl << endl;
            continue;
        }
        else if (pass1.size() == 0)
        {
            cout << "You have provided an empty passphrase." << endl; 
            cout << "If you continue, this " << verbose_ << " will be unencrypted!" << endl;
            
            while (true)
            {
                string yn;
                cout << "Do you wish to continue (Y/n)? ";
                cin >> yn;

                if (yn == "n")
                {
                    cout << endl;
                    break;
                }
                else if (yn == "Y")
                {
                    cout << "The " << verbose_ << " will be unencrypted!" << endl;
                    return SecureBinaryData();
                }
            }

            continue;
        }
        
        return SecureBinaryData(pass1);
    }
}

////////////////////////////////////////////////////////////////////////////////
SecureBinaryData TerminalPassphrasePrompt::promptForPassphrase(
    const set<BinaryData>& idSet)
{
    if (idSet.size() == 0)
        throw runtime_error("invalid id count");

    bool suppress = false;
    for (auto& id : idSet)
    {
        auto iter = countMap_.find(id);
        if (iter == countMap_.end())
            iter = countMap_.insert(make_pair(id, 0)).first;

        if (iter->second > 0)
            suppress = true;

        if (++(iter->second) > 3)
        {
            cout << "3 failed attempts, aborting" << endl << endl;
            exit(2);
            return SecureBinaryData();
        }
    }

    if (!suppress)
    {
        cout << endl << "Encrypted " << verbose_ << 
            ", please input the password for either of these key(s): " << endl;
    
        unsigned idCount = 1;
        for (auto& id : idSet)
        cout << " ." << idCount++ << ": " << id.toHexStr() << endl;
    }
        
    cout << " passhrase: ";

    string pass1;
    setEcho(false);
    cin >> pass1;
    setEcho(true);
    cout << endl;

    return SecureBinaryData(pass1);
}

////////////////////////////////////////////////////////////////////////////////
void TerminalPassphrasePrompt::setEcho(bool enable)
{
#ifdef WIN32
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE); 
    DWORD mode;
    GetConsoleMode(hStdin, &mode);

    if (!enable)
        mode &= ~ENABLE_ECHO_INPUT;
    else
        mode |= ENABLE_ECHO_INPUT;

    SetConsoleMode(hStdin, mode );
#else
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);

    if (!enable)
        tty.c_lflag &= ~ECHO;
    else
        tty.c_lflag |= ECHO;

    tcsetattr(STDIN_FILENO, TCSANOW, &tty);
#endif
}

////////////////////////////////////////////////////////////////////////////////
PassphraseLambda TerminalPassphrasePrompt::getLambda(const string& verbose)
{
    auto ptr = new TerminalPassphrasePrompt(verbose);
    shared_ptr<TerminalPassphrasePrompt> smartPtr(ptr);

    auto passLbd = [smartPtr](const set<BinaryData>& idSet)->SecureBinaryData
    {
        return smartPtr->prompt(idSet);
    };
    return passLbd;
}