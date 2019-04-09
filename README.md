
# Using Apktool to patch Android Java source code
## Target 
To tamper a `Boolean` value, i.e. the `Boolean bTamperingSucces = false;`, or some other code you have interest in. 

## Tools required
### apktool
 `apktool` can be feteched from [Apktool website](https://ibotpeaches.github.io/Apktool/).  Just follow the steps inside this page to install apktool. 

### adb 
`adb` is shipped with Android SDK, it can be found from directory `<your-some-path>/Android/sdk/platform-tools/adb`

### apksigner
`apksigner` is to sign your apk with a keystore file. This tool can be found at directory ``, and the usage is documented at [command-line apksigner](https://developer.android.com/studio/command-line/apksigner).

## Steps 
1. Clone the example project from [DecompileApk](https://github.com/russell-shizhen/DecompileApk). 
2. Find the already compiled apk file `DecompileApk/app/release/app-release.apk`.
3. Decompile it using **apktool**. 
    ```bash
    $ cd <your-path>/DecompileApk/app/release/
    $ apktool d --no-res -f app-release.apk
    ```
    You will see below outputs
    ```bash
    I: Using Apktool 2.4.0 on app-release.apk
    I: Copying raw resources...
    I: Baksmaling classes.dex...
    I: Copying assets and libs...
    I: Copying unknown files...
    I: Copying original files...
    ```
4. Look for `DecompileApk/app/release/app-release/smali/com/arophix/decompileapk/MainActivity.smali` under the smali code directory and find below code on line 40
    ```c
    const/4 p1, 0x0       
    ```
5. Just change `0x0` (meaning `false`) to `0x1` (meaning `true`)  and save the file.
6. Using **apktool** to build the tampered apk.
    ```c
    $ apktool b app-release
    ```
    You should see below outputs
    ```bash
    I: Using Apktool 2.4.0
    I: Checking whether sources has changed...
    I: Smaling smali folder into classes.dex...
    I: Checking whether resources has changed...
    I: Copying raw resources...
    I: Copying libs... (/lib)
    I: Building apk file...
    I: Copying unknown files/dir...
    I: Built apk...
    ```
7. Find the newly built apk from `dist` directory `DecompileApk/app/release/app-release/dist/app-release.apk`
8. Sign the apk using **apksigner** and keystore located at `DecompileApk/app/decompileapk.jks` (please modify the paths for keystore and apk per your own case accordingly), 
   ```bash
    $ <ANDROID_HOME>/sdk/build-tools/28.0.3/apksigner sign --ks ../decompileapk.jks app-release.apk
   ``` 
   You should see below outputs and enter the password `123456`
   ```bash
   $ Keystore password for signer #1:
   ```
9. Install the signed apk using adb command. 
    ```bash
    $ adb install <path-to-the-tampered-apk>/app-release.apk 
    ``` 
10. Instead of seeing `"Hello from C++"` from the screen, you should now see `"Hello, Android reverse engineer!"`. 