---
title: "Automated Testing On Real iOS Devices"
date: 2019-01-15T18:19:44+03:00
draft: false
tags: [appium, ios, automated-testing, xcode, webdriveragent, real-devices]
description: Automated testing is one of the popular topics of our time and almost indispensable. Usually it saves us from time and cost wasting and offers repeatability. In this article, I will explain how we can do automated tests on real iOS devices with Appium.
---

**Automated testing** is one of the popular topics of our time and almost indispensable. Usually it saves us from wasting time and offers repeatability. In this article, I will explain how we can do automated tests on real iOS devices with Appium.

**Appium** is an open source test automation framework for use with native, hybrid and mobile web apps.
It drives iOS, Android, and Windows apps using the WebDriver protocol.[[1]](https://appium.io/)

Before I begin to explain **"How to automate mobile tests?"**, I need to explain to you **"What the necessary things are?"** and **"How we can install?"**.

Let's start.

---

### What is HomeBrew

Homebrew is a free and open-source software package management system that simplifies the installation of software on macOS (and Linux). We will use it to install many applications in this post.

#### How to install HomeBrew

```bash
/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
```

---

### What is Node.js and npm

Node.js is an open-source, cross-platform JavaScript run-time environment that executes JavaScript code server-side.

npm is a package manager for the JavaScript programming language. It is the default package manager for the JavaScript runtime environment Node.js.

#### How to install Node

```bash
brew install node
```

---

**WARNING!** - _You need to switch Xcode-App before installing Appium_

```bash
sudo xcode-select --switch /Applications/Xcode.app/Contents/Developer
```

---

#### What is Appium

There is no need for a detailed explanation since I used the official explanation before, but I want to repeat that it is the core of our post.

#### How to install Appium

Appium:

```bash
npm install -g appium --no-shrinkwrap
```

Appium Desktop Application (contains Inspector):

```text
https://github.com/appium/appium-desktop/releases/
```

---

### What is ios-deploy

Install and debug iOS apps from the command line. Designed to work on un-jailbroken devices.[[2]](https://github.com/ios-control/ios-deploy)

#### How to install ios-deploy?

```bash
npm install -g ios-deploy
```

---

### What is Carthage

Carthage is intended to be the simplest way to add frameworks to your Cocoa application.

Carthage builds your dependencies and provides you with binary frameworks, but you retain full control over your project structure and setup. Carthage does not automatically modify your project files or your build settings.[[3]](https://github.com/Carthage/Carthage)

#### How to install Carthage

```bash
brew install carthage
```

---

**WARNING!** _You need to switch Xcode-App to Xcode Command Line Tools before installing **usbmuxd** and **libimobiledevice**_

```bash
sudo xcode-select --switch /Library/Developer/CommandLineTools/
```

---

### What is usbmuxd

A socket daemon to multiplex connections from and to iOS devices.[[4]](https://github.com/libimobiledevice/usbmuxd)

usbmuxd stands for "USB multiplexing daemon". This daemon is in charge of multiplexing connections over USB to an iOS device. To users, it means you can use various applications to interact with your device.

#### How to install usbmuxd

```bash
brew install --HEAD usbmuxd
```

---

### What is libimobiledevice

libimobiledevice is a cross-platform software library that talks the protocols to support iPhone, iPod Touch, iPad and Apple TV devices.

Unlike other projects, it does not depend on using any existing proprietary libraries and does not require jailbreaking.

It allows other software to easily access the device's filesystem, retrieve information about the device and it's internals, backup/restore the device, manage SpringBoard icons, manage installed applications, retrieve addressbook/calendars/notes and bookmarks and (using libgpod) synchronize music and video to the device.
[[5]](http://www.libimobiledevice.org/)

#### How to install libimobiledevice

```bash
brew install --HEAD libimobiledevice
```

---

**WARNING!** _You need to switch Xcode-App before installing **ideviceinstaller**_

```bash
sudo xcode-select --switch /Applications/Xcode.app/Contents/Developer
```

---

### What is ideviceinstaller

ideviceinstaller is a tool to interact with the installation_proxy
of an iOS device allowing to install, upgrade, uninstall, archive, restore
and enumerate installed or archived apps.[[6]](https://github.com/libimobiledevice/ideviceinstaller)

#### How to install ideviceinstaller

```bash
brew install ideviceinstaller
```

---

### What is ios-webkit-debug-proxy

The ios_webkit_debug_proxy (aka iwdp) proxies requests from usbmuxd daemon over a websocket connection, allowing developers to send commands to MobileSafari and UIWebViews on real and simulated iOS devices.[[7]](https://github.com/google/ios-webkit-debug-proxy)

#### How to install ios-webkit-debug-proxy

```bash
brew install ios-webkit-debug-proxy
```

---

### Setting Up WebDriverAgent with bootstrap.sh

After these installation processes, we need to run **bootstrap.sh** to prepare **WebDriverAgent** application.

Appium PATH:

```bash
cd /usr/local/lib/node_modules/appium/node_modules/appium-xcuitest-driver/WebDriverAgent
```

Appium Desktop Application PATH:

```bash
cd /Applications/Appium.app/Contents/Resources/app/node_modules/appium/node_modules/appium-xcuitest-driver/WebDriverAgent(**)
```

After that, we run the script with the command below.

```bash
bash ./Scripts/bootstrap.sh
```

---

**All your setups are complete.**

It is necessary to sign in Apple Developer Account via **WebDriverAgent.Xcode**.

_BTW, you need to add your iOS devices to Developer Account before starting test._

---

### Troubleshoots

If you're getting errors when you trying to install libimobiledevice, this is becoming from `usbmuxd` dependencies.

- First uninstalling libimobiledevice and usbmuxd and Installing on HEAD

```bash
brew update
brew uninstall --ignore-dependencies libimobiledevice
brew uninstall --ignore-dependencies usbmuxd
brew install --HEAD usbmuxd
brew unlink usbmuxd
brew link usbmuxd
brew install --HEAD libimobiledevice
```
