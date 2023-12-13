---
layout:	post
title:  "Analysis of Rhysida 0.1 Ransomware"
date:   2023-08-10 11:11:11 +0200
categories: [Malware Analysis]
tags: [Rhysida, Ransomware, MITRE ATT&CK, YARA]
---

## Introduction:

Earlier this year, in May, Rhysida, a new ransomware strain has surfaced. This ransomware operates on RaaS model. This ransomware is still at its early stage and its current version is called Rhysida 0.1. Although the ransomware is at its infancy, it has been linked to series of high-profile attacks and has been targeting several industries. According to HHS, it is listed as one of the top threats to healthcare sector.

<br>

## Case Study: Rhysida 0.1 Ransomware

## Identification:

**SHA256:** a864282fea5a536510ae86c77ce46f7827687783628e4f2ceb5bf2c41b8cd3c6  
**AV Detection:**  54/71 detected ([VirusTotal](https://www.virustotal.com/gui/file/a864282fea5a536510ae86c77ce46f7827687783628e4f2ceb5bf2c41b8cd3c6/details))

![](https://miro.medium.com/v2/resize:fit:700/1*qUQ2AiYogTvv6_G2WcfMIQ.png)

<br>

## Analysis:

### **Static Analysis:**

The analysis of the sample was started with the static analysis by examining the file headers and metadata. Using  **PeStudio**  tool, the compile-stamp was checked which indicate that the sample was developed on May 15 (Mon) 2023 at 16:29:10. This could be the actual timestamp of this sample considering its first attack was reported on May 17.

![](https://miro.medium.com/v2/resize:fit:700/1*MhG1gFu_IKIhKeHB6mB_0w.png)

After this, the strings of this sample were extracted using  **FLOSS**  tool and saved to a text file as:

    floss.exe 3pckfwua.exe > strings.txt

Some of the interesting strings found in this sample are:

![](https://miro.medium.com/v2/resize:fit:700/1*g46NilknyhnGe6WNBB_4Ow.png)

In the above figure:
-   The ransom note was found.
-   The strings related to PDF header and objects were also found. Also, the string ‘CriticalBreachDetected.pdf’ and the heading of the ransomware note ‘Critical Breach Detected’ matches. So, this sample could be using the ‘CriticalBreachDetected.pdf’ file as ransom note.

![](https://miro.medium.com/v2/resize:fit:700/1*FKT9dM5TkfcTQZiypU0IHA.png)

-   Also, the strings related to PDF trailer were found containing the metadata of its creation at 2023 May 15 at 16:28:56, which is around a minute before creating this executable sample. This further back up the creation date of the sample.

![](https://miro.medium.com/v2/resize:fit:700/1*dOyFpoEoBgZ3xCL1HKOGpg.png)

In the above figure:

-   The version of this ransomware sample, i.e., Rhysida-0.1 was found.
-   The path (C:/Users/Public/bg.jpg) where the background image will be dropped by the sample was also found.
-   Then, a series of commands (will be covered later in detail during dynamic analysis) were also found.

Since this ransomware is still at its infancy, a lot of information were easily extracted just with static analysis. But later with time, this ransomware may evolve enforcing obfuscation and anti-analysis to make the analysis challenging.

<br>

### **Dynamic Analysis:**

For the dynamic analysis, the sample was debugged using  **x64dbg**  tool. The program calls the GetSystemInfo API and then checks the number of processors of the victim machine, value in stack frame [rbp+80] after the call.

![](https://miro.medium.com/v2/resize:fit:700/1*STt-twWxlykM46J1cdKFag.png)

After that there is call to  **printf**  which prints the output to its console.

![](https://miro.medium.com/v2/resize:fit:700/1*7v-xfEYfg60gBDpu57o-jw.png)

The malware then constructs the string ‘Program:’ on stack with ‘stackstrings’ technique and then checks the path to its executable file.

![](https://miro.medium.com/v2/resize:fit:700/1*DRwcP8yBV2maIJQB7nVgeQ.png)

After that it call  **printf**  and prints the path of the malware in its console.

![](https://miro.medium.com/v2/resize:fit:700/1*YoJTiaQnfbPvibVaUd3qhw.png)

The sample then enumerate directories from A: to Z:. If it found any directory during that enumeration, it will enumerate the sub-directories as well.

![](https://miro.medium.com/v2/resize:fit:700/1*K7qigLJrXikagg7w9NoG7A.png)

It enumerates and list sub-directories using FindNextFile API.

![](https://miro.medium.com/v2/resize:fit:700/1*NL-R4gZ1gQV9l6j92iLzgQ.png)

For the directories and sub-directories found, the files inside them are encrypted with ChaCha20 algorithm, which references were found as shown below.

![](https://miro.medium.com/v2/resize:fit:700/1*96xRSGD2yAO2L6BJmlojVw.png)

The encrypted files are in .rhysida extension. And the ransom note dropped is a pdf file called ‘CriticalBreachDetected.pdf’, which was also discovered during static analysis.

![](https://miro.medium.com/v2/resize:fit:700/1*fd_BJpIQOU0u6hTH6FnRXA.png)

Also, this sample contains excluded directories and extensions. They were found when checking labels with  **Ghidra**  as shown in two figures below.

![](https://miro.medium.com/v2/resize:fit:700/1*ZGQSnqBMICOp-7kLPiKvOw.png)

The extensions that this sample excludes are .bat, .bin, .cab, .cmd, .com, .cur, .diagcab, .diagcfg, .diagpkg, .drv, .dll, .exe, .hlp, .hta, .ico, .lnk, .msi, .ocx, .ps1, .psm1, .scr, .sys, .ini thumbs, .db, .url, .iso and .cab.

![](https://miro.medium.com/v2/resize:fit:700/1*Mvu4wjIyJqJ8cdK0nRs_yg.png)

The directories that this sample excludes are Recycle Bin, Boot, Documents and Settings, PerfLogs, Program Files, Program Files (x86), ProgramData, Recovery, System Volume Information and Windows.

After completing enumerating (up to Z:) and encrypting files of found directories, the sample then executes different commands.

![](https://miro.medium.com/v2/resize:fit:700/1*t05xVchZhlRfHS2gfU3xTg.png)

For the execution of the command, the sample calls CreateProcess API. The commands executed were the same that were found during the string analysis.

![](https://miro.medium.com/v2/resize:fit:1000/1*UJ0sQ1IiVnDhNJ4SuBH6kQ.png)

This can be verified from Process Monitor capture as well.

![](https://miro.medium.com/v2/resize:fit:700/1*zqoxSUaT7zI8W36UNPw8zw.png)

Let's breakdown the commands executed by the sample. The first two commands that are executed are:

    cmd.exe /c reg delete "HKCU\Conttol Panel\Desktop" /v Wallpaper /f  
    cmd.exe /c reg delete "HKCU\Conttol Panel\Desktop" /v WallpaperStyle /f

-   Here, there is typo error with ‘Control’ written as ‘Conttol’. So, these two commands will execute but will fail to delete the targeted registry.

![](https://miro.medium.com/v2/resize:fit:591/1*ai8uPWbdtyJL8uAHweZW_w.png)

After that, the commands it tries to execute the following commands:

    cmd.exe /c reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\ActiveDesktop" /v NoChangingWallPaper /t REG_SZ /d 1 /f  
    cmd.exe /c reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\ActiveDesktop" /v NoChangingWallPaper /t REG_SZ /d 1 /f  
    cmd.exe /c reg add "HKCU\\Control Panel\\Desktop" /v Wallpaper /t REG_SZ /d "C:\\Users\\Public\\bg.jpg" /f  
    cmd.exe /c reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v Wallpaper /t REG_SZ /d "C:\\Users\\Public\\bg.jpg" /f  
    cmd.exe /c reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v WallpaperStyle /t REG_SZ /d 2 /f  
    cmd.exe /c reg add "HKCU\\Control Panel\\Desktop" /v WallpaperStyle /t REG_SZ /d 2 /f  
    rundll32.exe user32.dll,UpdatePerUserSystemParameters

-   With first two command, the sample add a new registry key NoChangingWallpaper under HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop and HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop and set it as 1.
-   With third command, the sample tries to add bg.jpg under Wallpaper registry key under HKCU\Control Panel\Desktop to set as wallpaper.
-   With fourth and fifth command, the sample add a new registry key WallpaperStyle with bg.jpg under HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System to setup wallpaper for login screen and set value 2 to set Stretch style.
-   The last command calls the UpdatePerUserSystemParameters function from the user32.dll to refresh the desktop wallpaper.

But no file bg.jpg were found to be dropped under C:\Users\Public during the analysis. So, no wallpaper for background and lock screen were set by this sample.

At last, the sample executes the following command:

    cmd.exe /c start powershell.exe -WindowStyle Hidden -Command Sleep -Milliseconds 500; Remove-Item -Force -Path " " -ErrorAction SilentlyContinue;

-   By this the sample creates an instance of PowerShell and sleeps for 0.5 second and then delete itself. But in this case, the sample was unable to delete itself.

<br>

## **MITRE ATT&CK TTP:**

![](https://miro.medium.com/v2/resize:fit:622/1*E3KY-LZ8FC7mFWqc0c-3TQ.png)

<br>

## **Detection with YARA:**

    rule Rhysida_Ransomware{  
    meta:  
            author= "Venus Chhantel"  
            filetype= "Win64 exe"  
            description= "Detecting Rhysida 0.1 Ransomware"  
    strings:  
            $version= {52 68 79 73 69 64 61 2D 30 2E 31}  
              
            $string1= {43 72 69 74 69 63 61 6C 42 72 65 61 63 68 44 65 74 65 63 74 65 64 2E 70 64 66}  
            $string2= {43 3A 2F 55 73 65 72 73 2F 50 75 62 6C 69 63 2F 62 67 2E 6A 70 67}  
            $string3= {72 68 79 73 69 64 61 66 6F 68 72 68 79 79 32 61 73 7A 69 37 62 6D 33 32 74 6E 6A 61 74 35 78 72 69 36 35 66 6F 70 63 78 6B 64 66 78 68 69 34 74 69 64 73 67 37 63 61 64 2E 6F 6E 69 6F 6E}  
            $string4= {63 68 61 63 68 61 32 30}  
            $string5= {49 6D 6D 65 64 69 61 74 65 20 52 65 73 70 6F 6E 73 65 20 52 65 71 75 69 72 65 64}  
            $string6= {54 68 69 73 20 69 73 20 61 6E 20 61 75 74 6F 6D 61 74 65 64 20 61 6C 65 72 74 20 66 72 6F 6D 20 63 79 62 65 72 73 65 63 75 72 69 74 79 20 74 65 61 6D 20 52 68 79 73 69 64 61}  
      
            $cmd1= {63 6D 64 2E 65 78 65 20 2F 63 20 72 65 67 20 64 65 6C 65 74 65 20 22 48 4B 43 55 5C 43 6F 6E 74 ?? 6F 6C 20 50 61 6E 65 6C 5C 44 65 73 6B 74 6F 70 22 20 2F 76 20 57 61 6C 6C 70 61 70 65 72 20 2F 66}  
            $cmd2= {63 6D 64 2E 65 78 65 20 2F 63 20 72 65 67 20 64 65 6C 65 74 65 20 22 48 4B 43 55 5C 43 6F 6E 74 ?? 6F 6C 20 50 61 6E 65 6C 5C 44 65 73 6B 74 6F 70 22 20 2F 76 20 57 61 6C 6C 70 61 70 65 72 53 74 79 6C 65 20 2F 66}  
            $cmd3= {63 6D 64 2E 65 78 65 20 2F 63 20 72 65 67 20 61 64 64 20 22 48 4B 43 55 5C 53 6F 66 74 77 61 72 65 5C 4D 69 63 72 6F 73 6F 66 74 5C 57 69 6E 64 6F 77 73 5C 43 75 72 72 65 6E 74 56 65 72 73 69 6F 6E 5C 50 6F 6C 69 63 69 65 73 5C 41 63 74 69 76 65 44 65 73 6B 74 6F 70 22 20 2F 76 20 4E 6F 43 68 61 6E 67 69 6E 67 57 61 6C 6C 50 61 70 65 72 20 2F 74 20 52 45 47 5F 53 5A 20 2F 64 20 31 20 2F 66}  
            $cmd4= {63 6D 64 2E 65 78 65 20 2F 63 20 72 65 67 20 61 64 64 20 22 48 4B 43 55 5C 43 6F 6E 74 72 6F 6C 20 50 61 6E 65 6C 5C 44 65 73 6B 74 6F 70 22 20 2F 76 20 57 61 6C 6C 70 61 70 65 72 20 2F 74 20 52 45 47 5F 53 5A 20 2F 64 20 22 43 3A 5C 55 73 65 72 73 5C 50 75 62 6C 69 63 5C 62 67 2E 6A 70 67 22 20 2F 66}  
            $cmd5= {63 6D 64 2E 65 78 65 20 2F 63 20 72 65 67 20 61 64 64 20 22 48 4B 4C 4D 5C 53 6F 66 74 77 61 72 65 5C 4D 69 63 72 6F 73 6F 66 74 5C 57 69 6E 64 6F 77 73 5C 43 75 72 72 65 6E 74 56 65 72 73 69 6F 6E 5C 50 6F 6C 69 63 69 65 73 5C 53 79 73 74 65 6D 22 20 2F 76 20 57 61 6C 6C 70 61 70 65 72 20 2F 74 20 52 45 47 5F 53 5A 20 2F 64 20 22 43 3A 5C 55 73 65 72 73 5C 50 75 62 6C 69 63 5C 62 67 2E 6A 70 67 22 20 2F 66}  
            $cmd6= {63 6D 64 2E 65 78 65 20 2F 63 20 72 65 67 20 61 64 64 20 22 48 4B 4C 4D 5C 53 6F 66 74 77 61 72 65 5C 4D 69 63 72 6F 73 6F 66 74 5C 57 69 6E 64 6F 77 73 5C 43 75 72 72 65 6E 74 56 65 72 73 69 6F 6E 5C 50 6F 6C 69 63 69 65 73 5C 53 79 73 74 65 6D 22 20 2F 76 20 57 61 6C 6C 70 61 70 65 72 53 74 79 6C 65 20 2F 74 20 52 45 47 5F 53 5A 20 2F 64 20 32 20 2F 66}  
            $cmd7= {63 6D 64 2E 65 78 65 20 2F 63 20 72 65 67 20 61 64 64 20 22 48 4B 43 55 5C 43 6F 6E 74 72 6F 6C 20 50 61 6E 65 6C 5C 44 65 73 6B 74 6F 70 22 20 2F 76 20 57 61 6C 6C 70 61 70 65 72 53 74 79 6C 65 20 2F 74 20 52 45 47 5F 53 5A 20 2F 64 20 32 20 2F 66}  
            $cmd8= {72 75 6E 64 6C 6C 33 32 2E 65 78 65 20 75 73 65 72 33 32 2E 64 6C 6C 2C 55 70 64 61 74 65 50 65 72 55 73 65 72 53 79 73 74 65 6D 50 61 72 61 6D 65 74 65 72 73}  
            $cmd9= {63 6D 64 2E 65 78 65 20 2F 63 20 73 74 61 72 74 20 70 6F 77 65 72 73 68 65 6C 6C 2E 65 78 65 20 2D 57 69 6E 64 6F 77 53 74 79 6C 65 20 48 69 64 64 65 6E 20 2D 43 6F 6D 6D 61 6E 64 20 53 6C 65 65 70 20 2D 4D 69 6C 6C 69 73 65 63 6F 6E 64 73 20 ?? ?? ?? 3B}  
            $cmd10= {52 65 6D 6F 76 65 2D 49 74 65 6D 20 2D 46 6F 72 63 65 20 2D 50 61 74 68 20 22}  
            $cmd11= {22 20 2D 45 72 72 6F 72 41 63 74 69 6F 6E 20 53 69 6C 65 6E 74 6C 79 43 6F 6E 74 69 6E 75 65 3B}  
      
    condition:  
            uint16(0) == 0x5A4D and  
            (  
                    $version and   
                    4 of ($string*) and  
                    5 of ($cmd*)  
            )  
    }

<br>

## **Conclusion:**

The Rhysida 0.1 ransomware is still at its early stage and has some bugs in it as found during the analysis. But precautions must still be taken to prevent or lower the risk from it since this ransomware has been connected to high-profile attacks soon after its release.
