- # purple-instagram
Instagram protocol plugin for libpurple

Prerequisites
-
Make sure you are running the most recent build of pidgin/libpurple (2.13.0)

install necessary development libraries if not already present:
```bash
  sudo apt install libglib2.0-dev
  sudo apt install libjson-glib-dev
  sudo apt install libpurple-dev
  sudo apt update 
``` 
Of course, if you are using another distribution such as fedora, you would replace apt with the relevant package manager. (e.g: yum or dnf)

Linux
-
```bash
  git clone https://github.com/SherbetS44105/purple-instagram.git
  cd ~/purple-instagram
  make
  sudo make install
```

after compiled, copy the libinstagram.so file into the ./purple/plugins directory, wherever that may be on your computer.

Windows
-
To download for Windows, extract the dll file found here: https://eion.robbmob.com/libinstagram.dll to ```%APPDATA%/.purple/plugins. ```
