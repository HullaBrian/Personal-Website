---
layout: post
title: So You Created a File on Windows
subtitle: ""
thumbnail-img: /assets/img/autopsy-initial-file.png
share-img: /assets/img/command-output.png
author: Jonathan Beierle
tags: ["Digital Forensics"]
---

- [Introduction](#introduction)
- [NTFS](#introduction)
- [File Creation: It's Aliiiiiive!](#file-creation-its-aliiiiiive)
    - [True File System Location](#true-file-system-location)
    - [MFT](#mft)
    - [USN Journal](#usn-journal)
    - [Event Logs](#event-logs)
- [Conclusion](#conclusion)

# Introduction
Knowing what happened on a file system is crucial to performing Digital
Forensics. I mean, what happens if an attacker dropped malware to disk and did
nasty things? Having visibility into exactly what happend is extremely important.

Now, going on a deep dive into an instance of malware being dropped onto a
Windows machine would provide an understanding of the concept, but in this post
I'd like to abstract away from general security for a moment to simply focus
on the artifacts generated when a file is created on a Windows machine using an
NTFS file system.

# NTFS
**New Technology File System** (**NTFS**) is a proprietary file system developed
by Microsoft that is currently the standard file system used in Windows operating
systems. While it's initial release was done in 1993, it's still around to this
day because of the many features that it brings to the table. Below are a few
key forensic attributes and artifacts that allow investigators to pull
information from NTFS:
- MFT Entries
- USN Journal
- File Metadata
- File Slack and Unallocated Space
- File Signatures

For the purposes of this post, I'll be mostly focussing on the MFT and USN
Journal, however all of the artifacts and attributes I mentioned above are still
vital to a proper digital investigation.

# File Creation: It's Aliiiiiive!
To start, I need to ensure that I don't have extra noise on the file system, I'll
create a brand new `Windows 10 Pro N` VM. Next, I'll login, open file explorer,
and create a new file called `HELLO-WORLD.txt` in the `C:\Users\user\Documents`
directory.

![alt text](/assets/img/file-creation.png)

Now, I need to be able to access all forensic artifacts in a way that nothing will
change while I'm working, so I turn off the VM and copy the `.vmdk` file to a
separate DFIR VM that has `autopsy` installed. Before doing anything that could
possibly result in a modification to the virtual machine's disk, it's best to get
a hash of it to identify if a change was made. On the DFIR VM I ran the
`Get-FileHash` Powershell Cmdlet.

| File Name      | Hash(SHA-256)                                                    |
|----------------|------------------------------------------------------------------|
| Windows10.vmdk | E97025F4DEA392AAEA238E0CB14C8BD31A334544347ADF203E2D619A134866A9 |

I then loaded the `.vmdk` file into autopsy to investigate.

## True File System Location
Perhaps the most obvious place to find a given file is the place it was created.
In the case of `HELLO-WORLD.txt`, it was located on volume 6 of the .vmdk file
specifically under the path:
`/img_Windows10.vmdk/vol_vol6/Users/user/Documents/HELLO-WORLD.txt`

![alt text](/assets/img/autopsy-initial-file.png)

## MFT
The **Master File Table** (**MFT**) is perhaps one of the most important
artifacts from NTFS in that it stores metadata for every file and directory on a
volume. For this example, at least, the MFT for the VM can be found in the path
`/img_Windows10.vmdk/vol_vol6/$MFT`.

To find what's left behind by `HELLO-WORLD.txt` in the MFT, I first extracted it
using autopsy, then opened it using the `MFT Explorer` tool.

![alt text](/assets/img/mft-view.png)

As seen in the above screenshot, there's a lot of valuable information that can be
recovered about a given file from the MFT, including, but not limited to:
- Creation time
- Modification time
- Last access time
- Record change time

## USN Journal
USN, or Update Sequence Number, is a vital component of NTFS. The USN Journal is
essentially a change journal feature that logs file and directory changes on a given 
NTFS volume. From my understanding the difference between the MFT and USN Journal
is that the MFT is current information regarding the file system, while the USN
journal acts more as a log of changes.

To find what's left behind by `HELLO-WORLD.txt` in the USN, I first extracted it
using autopsy from the path `/img_Windows10.vmdk/vol_vol6/$Extend/$UsnJrnl:$J`.
I then used the `MFTECmd` tool from the Eric Zimmerman suite of tools to analyse
any artifacts by converting the USN to a .csv file (see command used below)

`C:\Tools\Zimmerman\MFTECmd.exe -f '.\$UsnJrnl_$J' --csv . --csvf MFT-J.csv`

Then, I used the `TimelineExplorer` tool to view the extracted data

`C:\Tools\Zimmerman\TimelineExplorer\TimelineExplorer.exe .\MFT-J.csv`

![alt text](/assets/img/command-output.png)

After the TimelineExplorer opened, I filtered all `Name` entries for
`HELLO-WORLD.txt`, which resulted in the following table output

![alt text](/assets/img/usn-journal.png)

As you can see, simply creating a file has produced several artifacts within
the USN. For starters, we first see that a new text file is created, called
`New Text Document.txt` (`FileCreate`), which indicated that it was made by a
"right-click creation" in the File Explorer. It is then renamed to `HELLO-WORLD.txt`
(`RenameNewName`). Afterwards, its contents are modified (`DataExtend`) to add data.

## Event Logs
Unfortunately, due to the default behavior of Windows, file creation events are not
logged. However, there are ways to log this by enforcing audits on file creation.
This can be done via GPO or other tools such as Sysmon. The closest thing to default
behavior for logging file creation is the USN Journal.

# Conclusion
NTFS has a multitude of place in which artifacts can reside. From the MFT to the USN
Journal, you can get a lot of information about a file. While there are significantly
more ways to potentially find if a file was moved, if it was tampered with, or opened
in a specific place, I hope this blog post has shed a little more light on NTFS
digital artifacts.