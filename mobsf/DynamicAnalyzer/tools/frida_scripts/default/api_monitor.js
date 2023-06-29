// MobSF Android API Monitor
// Inspired from: https://github.com/realgam3/ReversingAutomation/blob/master/Frida/Android-DynamicHooks/DynamicHooks.js
var apis = [{
    class: 'android.os.Process',
    method: 'start',
    name: 'Process'
}, {
    class: 'android.app.ActivityManager',
    method: 'killBackgroundProcesses',
    name: 'Process'
}, {
    class: 'android.os.Process',
    method: 'killProcess',
    name: 'Process'
}, {
    class: 'java.lang.Runtime',
    method: 'exec',
    name: 'Command'
}, {
    class: 'java.lang.ProcessBuilder',
    method: 'start',
    name: 'Command'
}, {
    class: 'java.lang.Runtime',
    method: 'loadLibrary',
    name: 'Java Native Interface'
}, {
    class: 'java.lang.Runtime',
    method: 'load',
    name: 'Java Native Interface'
}, {
    class: 'android.webkit.WebView',
    method: 'loadUrl',
    name: 'WebView'
}, {
    class: 'android.webkit.WebView',
    method: 'loadData',
    name: 'WebView'
}, {
    class: 'android.webkit.WebView',
    method: 'loadDataWithBaseURL',
    name: 'WebView'
}, {
    class: 'android.webkit.WebView',
    method: 'addJavascriptInterface',
    name: 'WebView'
}, {
    class: 'android.webkit.WebView',
    method: 'evaluateJavascript',
    name: 'WebView'
}, {
    class: 'android.webkit.WebView',
    method: 'postUrl',
    name: 'WebView'
}, {
    class: 'android.webkit.WebView',
    method: 'postWebMessage',
    name: 'WebView',
    target: 6
}, {
    class: 'android.webkit.WebView',
    method: 'savePassword',
    name: 'WebView'
}, {
    class: 'android.webkit.WebView',
    method: 'setHttpAuthUsernamePassword',
    name: 'WebView'
}, {
    class: 'android.webkit.WebView',
    method: 'getHttpAuthUsernamePassword',
    name: 'WebView'
}, {
    class: 'android.webkit.WebView',
    method: 'setWebContentsDebuggingEnabled',
    name: 'WebView'
}, {
    class: 'libcore.io.IoBridge',
    method: 'open',
    name: 'File IO'
},
/* {
    // so much calls
    class: 'java.io.FileOutputStream',
    method: 'write',
    name: 'File IO'
}, {
    class: 'java.io.FileInputStream',
    method: 'read',
    name: 'File IO'
}, */
{
    class: 'android.content.ContextWrapper',
    method: 'openFileInput',
    name: 'File IO'
}, {
    class: 'android.content.ContextWrapper',
    method: 'openFileOutput',
    name: 'File IO'
}, {
    class: 'android.content.ContextWrapper',
    method: 'deleteFile',
    name: 'File IO'
},
/*
// crashes app on android 7
{
    class: 'android.app.SharedPreferencesImpl',
    method: 'getString',
    name: 'File IO - Shared Preferences'
}, {
    class: 'android.app.SharedPreferencesImpl',
    method: 'contains',
    name: 'File IO - Shared Preferences'
}, {
    class: 'android.app.SharedPreferencesImpl',
    method: 'getInt',
    name: 'File IO - Shared Preferences'
}, {
    class: 'android.app.SharedPreferencesImpl',
    method: 'getFloat',
    name: 'File IO - Shared Preferences'
}, {
    class: 'android.app.SharedPreferencesImpl',
    method: 'getLong',
    name: 'File IO - Shared Preferences'
}, {
    class: 'android.app.SharedPreferencesImpl',
    method: 'getBoolean',
    name: 'File IO - Shared Preferences'
}, {
    class: 'android.app.SharedPreferencesImpl',
    method: 'getStringSet',
    name: 'File IO - Shared Preferences'
}, {
    class: 'android.app.SharedPreferencesImpl$EditorImpl',
    method: 'putString',
    name: 'File IO - Shared Preferences'
}, {
    class: 'android.app.SharedPreferencesImpl$EditorImpl',
    method: 'putStringSet',
    name: 'File IO - Shared Preferences'
}, {
    class: 'android.app.SharedPreferencesImpl$EditorImpl',
    method: 'putInt',
    name: 'File IO - Shared Preferences'
}, {
    class: 'android.app.SharedPreferencesImpl$EditorImpl',
    method: 'putFloat',
    name: 'File IO - Shared Preferences'
}, {
    class: 'android.app.SharedPreferencesImpl$EditorImpl',
    method: 'putBoolean',
    name: 'File IO - Shared Preferences'
}, {
    class: 'android.app.SharedPreferencesImpl$EditorImpl',
    method: 'putLong',
    name: 'File IO - Shared Preferences'
}, {
    class: 'android.app.SharedPreferencesImpl$EditorImpl',
    method: 'remove',
    name: 'File IO - Shared Preferences'
},
*/
{
    class: 'android.content.ContextWrapper',
    method: 'openOrCreateDatabase',
    name: 'Database'
}, {
    class: 'android.content.ContextWrapper',
    method: 'databaseList',
    name: 'Database'
}, {
    class: 'android.content.ContextWrapper',
    method: 'deleteDatabase',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'execSQL',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'deleteDatabase',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'getPath',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'insert',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'insertOrThrow',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'insertWithOnConflict',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'openDatabase',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'openOrCreateDatabase',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'query',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'queryWithFactory',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'rawQuery',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'rawQueryWithFactory',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'update',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'updateWithOnConflict',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'compileStatement',
    name: 'Database'
}, {
    class: 'android.database.sqlite.SQLiteDatabase',
    method: 'create',
    name: 'Database'
}, {
    class: 'android.content.ContextWrapper',
    method: 'sendBroadcast',
    name: 'IPC',
    only_severity: true
}, {
    class: 'android.content.ContextWrapper',
    method: 'sendStickyBroadcast',
    name: 'IPC'
}, {
    class: 'android.content.ContextWrapper',
    method: 'startActivity',
    name: 'IPC',
    only_severity: true
}, {
    class: 'android.content.ContextWrapper',
    method: 'startService',
    name: 'IPC',
    only_severity: true
}, {
    class: 'android.content.ContextWrapper',
    method: 'stopService',
    name: 'IPC'
}, {
    class: 'android.content.ContextWrapper',
    method: 'registerReceiver',
    name: 'IPC',
    only_severity: true
}, {
    class: 'android.app.PendingIntent',
    method: 'getActivity',
    name: 'IPC',
    only_severity: true
}, {
    class: 'android.app.PendingIntent',
    method: 'getBroadcast',
    name: 'IPC',
    only_severity: true
}, {
    class: 'android.app.PendingIntent',
    method: 'getService',
    name: 'IPC',
    only_severity: true
}, {
    class: 'android.app.ContextImpl',
    method: 'registerReceiver',
    name: 'Binder',
    only_severity: true
}, {
    class: 'android.app.ActivityThread',
    method: 'handleReceiver',
    name: 'Binder'
}, {
    class: 'android.app.Activity',
    method: 'startActivity',
    name: 'Binder',
    only_severity: true
}, {
    class: 'javax.crypto.spec.SecretKeySpec',
    method: '$init',
    name: 'Crypto'
}, {
    class: 'javax.crypto.Cipher',
    method: 'doFinal',
    name: 'Crypto'
}, {
    class: 'java.security.MessageDigest',
    method: 'digest',
    name: 'Crypto - Hash'
}, {
    class: 'java.security.MessageDigest',
    method: 'update',
    name: 'Crypto - Hash'
}, {
    class: 'android.telephony.TelephonyManager',
    method: 'getDeviceId',
    tag:'imei',
    name: 'Device Info'
}, {
    class: 'android.telephony.TelephonyManager',
    method: 'getImei',
    tag:'imei',
    name: 'Device Info'
}, {
    class: 'android.telephony.TelephonyManager',
    method: 'getMeid',
    tag:'meid',
    name: 'Device Info',
    target: 8
}, {
    class: 'android.telephony.TelephonyManager',
    method: 'getSubscriberId',
    tag:'imsi',
    name: 'Device Info'
}, {
    class: 'android.telephony.TelephonyManager',
    method: 'getSimSerialNumber',
    tag:'iccid',
    name: 'Device Info'
}, {
    class: 'android.telephony.TelephonyManager',
    method: 'getUiccCardsInfo',
    tag:'imsi',
    name: 'Device Info',
    target: 10
}, {
    class: 'android.telephony.TelephonyManager',
    method: 'getLine1Number',
    tag:'imsi',
    name: 'Device Info'
}, {
    class: 'android.telephony.TelephonyManager',
    method: 'getAllCellInfo',
    tag:'location',
    name: 'Device Info'
}, {
    class: 'android.telephony.TelephonyManager',
    method: 'getNetworkOperator',
    name: 'Device Info'
}, {
    class: 'android.telephony.TelephonyManager',
    method: 'getNetworkOperatorName',
    name: 'Device Info'
}, {
    class: 'android.telephony.TelephonyManager',
    method: 'getSimOperatorName',
    name: 'Device Info'
}, {
    class: 'android.telephony.TelephonyManager',
    method: 'getSimCountryIso',
    name: 'Device Info'
}, {
    class: 'android.telephony.TelephonyManager',
    method: 'getNetworkCountryIso',
    name: 'Device Info'
}, {
    class: 'android.telephony.TelephonyManager',
    method: 'getDeviceSoftwareVersion',
    name: 'Device Info'
}, {
    class: 'android.net.wifi.WifiInfo',
    method: 'getMacAddress',
    tag:'mac_address',
    name: 'Device Info'
}, {
    class: 'android.net.wifi.WifiInfo',
    method: 'getBSSID',
    tag:'mac_address',
    name: 'Device Info'
}, {
    class: 'android.net.wifi.WifiInfo',
    method: 'getIpAddress',
    tag:'ip_address',
    name: 'Device Info'
}, {
    class: 'android.net.wifi.WifiInfo',
    method: 'getNetworkId',
    tag:'network_id',
    name: 'Device Info'
},  {
    class: 'java.net.NetworkInterface',
    method: 'getNetworkInterfaces',
    tag:'network_list',
    name: 'Device Info'
}, {
    class: 'android.os.Debug',
    method: 'isDebuggerConnected',
    name: 'Device Info'
}, {
    class: 'android.app.ApplicationPackageManager',
    method: 'getInstallerPackageName',
    name: 'Device Info'
}, {
    class: 'android.app.ApplicationPackageManager',
    method: 'getInstalledModules',
    name: 'Device Info',
    target: 10,
}, {
    class: 'android.app.ApplicationPackageManager',
    method: 'getApplicationInfo',
    tag:'app_third_info',
    name: 'Device Info',
    only_severity: true
}, {
    class: 'android.app.ApplicationPackageManager',
    method: 'getPackageInfo',
    tag:'app_third_info',
    name: 'Device Info',
    only_severity: true
}, {
    class: 'android.app.ApplicationPackageManager',
    method: 'getPackageArchiveInfo',
    tag:'app_third_info',
    name: 'Device Info'
}, {
    class: 'android.app.ApplicationPackageManager',
    method: 'getInstalledApplications',
    tag:'app_list',
    name: 'Device Info'
}, {
    class: 'android.app.ApplicationPackageManager',
    method: 'getInstalledPackages',
    tag:'app_list',
    name: 'Device Info'
}, {
    class: 'android.app.ApplicationPackageManager',
    method: 'queryIntentServices',
    tag:'app_list',
    name: 'Device Info'
}, {
    class: 'android.app.ApplicationPackageManager',
    method: 'queryBroadcastReceivers',
    tag:'app_list',
    name: 'Device Info'
},{
    class: 'android.app.ApplicationPackageManager',
    method: 'queryIntentActivities',
    tag:'app_list',
    name: 'Device Info'
},{
    class: 'android.app.ApplicationPackageManager',
    method: 'queryIntentContentProviders',
    tag:'app_list',
    name: 'Device Info'
}, {
    class: 'android.app.ActivityManager',
    method: 'getRunningAppProcesses',
    tag:'app_list',
    name: 'Device Info'
}, {
    class: 'android.app.ActivityManager',
    method: 'getRunningTasks',
    tag:'app_list',
    name: 'Device Info'
}, {
    class: 'android.content.Context',
    method: 'getSystemService',
    name: 'Device Info',
    only_severity: true
}, {
    class: 'android.content.ContextWrapper',
    method: 'getSystemService',
    name: 'Device Info',
    only_severity: true
}, {
    class: 'android.view.ContextThemeWrapper',
    method: 'getSystemService',
    name: 'Device Info',
    only_severity: true
}, {
    class: 'android.provider.Settings$Secure',
    method: 'getString',
    name: 'Device Info',
    tag:'android_id',
    only_severity: true
}, {
    class: 'java.net.URL',
    method: 'openConnection',
    name: 'Network'
}, {
    class: 'org.apache.http.impl.client.AbstractHttpClient',
    method: 'execute',
    name: 'Network'
}, {
    class: 'com.android.okhttp.internal.huc.HttpURLConnectionImpl',
    method: 'getInputStream',
    name: 'Network'
}, {
    class: 'com.android.okhttp.internal.http.HttpURLConnectionImpl',
    method: 'getInputStream',
    name: 'Network'
}, {
    class: 'dalvik.system.BaseDexClassLoader',
    method: 'findResource',
    name: 'Dex Class Loader'
}, {
    class: 'dalvik.system.BaseDexClassLoader',
    method: 'findResources',
    name: 'Dex Class Loader'
}, {
    class: 'dalvik.system.BaseDexClassLoader',
    method: 'findLibrary',
    name: 'Dex Class Loader'
}, {
    class: 'dalvik.system.DexFile',
    method: 'loadDex',
    name: 'Dex Class Loader'
}, {
    class: 'dalvik.system.DexFile',
    method: 'loadClass',
    name: 'Dex Class Loader'
}, {
    class: 'dalvik.system.DexClassLoader',
    method: '$init',
    name: 'Dex Class Loader'
}, {
    class: 'android.util.Base64',
    method: 'decode',
    name: 'Base64'
}, {
    class: 'android.util.Base64',
    method: 'encode',
    name: 'Base64'
}, {
    class: 'android.util.Base64',
    method: 'encodeToString',
    name: 'Base64'
}, {
    class: 'android.app.ApplicationPackageManager',
    method: 'setComponentEnabledSetting',
    name: 'System Manager'
}, {
    class: 'android.app.NotificationManager',
    method: 'notify',
    name: 'System Manager'
}, {
    class: 'android.telephony.TelephonyManager',
    method: 'listen',
    name: 'System Manager'
}, {
    class: 'android.content.BroadcastReceiver',
    method: 'abortBroadcast',
    name: 'System Manager'
}, {
    class: 'android.telephony.SmsManager',
    method: 'sendTextMessage',
    name: 'SMS'
}, {
    class: 'android.telephony.SmsManager',
    method: 'sendMultipartTextMessage',
    name: 'SMS'
}, {
    class: 'android.content.ContentResolver',
    method: 'query',
    name: 'Device Data'
}, {
    class: 'android.content.ContentResolver',
    method: 'registerContentObserver',
    name: 'Device Data'
}, {
    class: 'android.content.ContentResolver',
    method: 'insert',
    name: 'Device Data'
}, {
    class: 'android.content.ContentResolver',
    method: 'delete',
    name: 'Device Data'
}, {
    class: 'android.accounts.AccountManager',
    method: 'getAccountsByType',
    name: 'Device Data'
}, {
    class: 'android.accounts.AccountManager',
    method: 'getAccounts',
    name: 'Device Data'
}, {
    class: 'android.location.Location',
    method: 'getLatitude',
    name: 'Device Data'
}, {
    class: 'android.location.Location',
    method: 'getLongitude',
    name: 'Device Data'
}, {
    class: 'android.media.AudioRecord',
    method: 'startRecording',
    name: 'Device Data'
}, {
    class: 'android.media.MediaRecorder',
    method: 'start',
    name: 'Device Data'
}, {
    class: 'android.os.SystemProperties',
    method: 'get',
    name: 'Device Data'
}
];



function isArguments(a, b) {
// high\warning\info
    var clazz = a.class;
    var method = a.method;
    // send('[API Monitor] isArguments arg: ' + clazz + '.' + method);
    try {
        if ("startActivity" === method) {
            return startActivityImp();
        } else if ("startService" === method) {
            return startServiceImp();
        } else if ("registerReceiver" === method) {
            return registerReceiverImp();
        }  else if ("sendBroadcast" === method) {
            return sendBroadcastImp();
        } else if ("android.app.PendingIntent" === clazz
            && ("getActivity" === method
                || "getBroadcast" === method
                || "getService" === method)) {
            return pendingIntentImp();
        } else if ("android.provider.Settings$Secure" === clazz
            && "getString" === method) {
            return androidIdImp();
        } else if ("getSystemService" === method){
            return getSystemServiceImp();
        } else if ("android.app.ApplicationPackageManager" === clazz
            && "getApplicationInfo" == method) {
            return getApplicationInfoImp(method);
        } else if ("android.app.ApplicationPackageManager" === clazz
            && "getPackageInfo" == method) {
            return getPackageInfoImp(method);
        }
    } catch (err) {
        send('[API Monitor] isArguments err: ' + clazz + '.' + method + " [\"Error\"] => " + err);
    }
    // send('[API Monitor] isArguments return true ');
    return {
        severity_is: false
    };


    function onlyActionIntent(intent) {
        let data = intent.getData();
        let component = intent.getComponent();
        let categories = intent.getCategories();
        let pak = intent.getPackage();
        // send('[API Monitor] onlyActionIntent data ' + typeof data);
        // send('[API Monitor] onlyActionIntent component ' + typeof component);
        // send('[API Monitor] onlyActionIntent categories ' + typeof categories);
        // send('[API Monitor] onlyActionIntent package ' + typeof pak);
        if ((typeof data === 'undefined' || data === null) &&
            (typeof component === 'undefined' || component === null) &&
            (typeof categories === 'undefined' || categories === null) &&
            (typeof pak === 'undefined' || pak === null)) {
            // send('[API Monitor] onlyActionIntent return true ');
            return {
                severity_is:true,
                severity:'warning',
                severity_msg: 'only has Action'
            };
        } else {
            // send('[API Monitor] onlyActionIntent return false ');
            return {
                severity_is:false
            };
        }
    }

    function sendBroadcastImp() {
        var len_arg = len(b);
        if (len_arg <= 1) {
            return {
                severity_is: true,
                severity: 'warning',
                severity_msg: 'No permissions are set for sending broadcasts'
            };
        } else {
            return {
                severity_is: false
            };
        }
    }
    function registerReceiverImp() {
        var len_arg = len(b);
        if (len_arg <= 3) {
            return {
                severity_is: true,
                severity: 'warning',
                severity_msg: 'There are no set permissions for dynamically registered broadcasts'
            };
        } else {
            return {
                severity_is: false
            };
        }
    }

    function startActivityImp() {
        // send('[API Monitor] startActivityImp ');
        var intent = b[0];
        return onlyActionIntent(intent);
    }
    function startServiceImp() {
        // send('[API Monitor] startServiceImp ');
        var intent = b[0];
        return onlyActionIntent(intent);
    }
    function pendingIntentImp() {
        // send('[API Monitor] pendingIntentImp ');
        var intent = b[2];
        return onlyActionIntent(intent);
    }

    function androidIdImp() {
        // send('[API Monitor] pendingIntentImp ');
        var arg_name = b[1];
        if ("android_id" === arg_name) {
            return {
                severity_is: true,
                tag: 'android_id'
            };
        }
        return {
            severity_is: false
        };
    }
    function getSystemServiceImp() {
        // send('[API Monitor] pendingIntentImp ');
        var serviceName = b[0];
        if (typeof serviceName !== 'string') {
            serviceName = getContext().getSystemServiceName(serviceName);
        }
        var ty_is = true;
        var type_n;
        if ("location" === serviceName) {
            type_n = 'location'
        } else if ("clipboard" === serviceName) {
            type_n = 'clipboard'
        } else if ("usagestats" === serviceName) {
            type_n = 'usage_stats'
        } else {
            ty_is = false
        }
        return {
                severity_is:ty_is,
                tag: type_n
            };
    }
    function getApplicationInfoImp() {
        // send('[API Monitor] pendingIntentImp ');
        var packageName_arg = b[0];
        const packageName = getContext().getPackageName();

        var ty_is = true;
        var type_n;
        if (packageName !== packageName_arg) {
            type_n = 'app_third_info'
        } else {
            ty_is = false
        }
        return {
                severity_is:ty_is,
                tag: type_n
            };
    }
    function getPackageInfoImp() {
        // send('[API Monitor] pendingIntentImp ');
        var packageName_arg = b[0];
        const packageName = getContext().getPackageName();
        var ty_is = true;
        var ty = 'warning'
        var ty_msg = ''
        var type_n;
        if (typeof packageName_arg !== 'string'){
            packageName_arg = packageName_arg.getPackageName()
        }
        if (packageName !== packageName_arg) {
            ty_msg = 'get third app info'
            type_n = 'app_third_info'
        } else {
            ty_is = false
        }
        return {
            severity_is: ty_is,
            tag: type_n
        };
    }
    function getContext() {
        return Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
    }
}

// Dynamic Hooks
function hook(api, callback) {
    var Exception = Java.use('java.lang.Exception');
    var toHook;
    try {
        var clazz = api.class;
        var method = api.method;
        var name = api.name;
        var tag = api.tag;
        try {
            if (api.target && parseInt(Java.androidVersion, 10) < api.target) {
                // send('[API Monitor] Not Hooking unavailable class/method - ' + clazz + '.' + method)
                return
            }
            // Check if class and method is available
            toHook = Java.use(clazz)[method];
            if (!toHook) {
                send('[API Monitor] Cannot find ' + clazz + '.' + method);
                return
            }
        } catch (err) {
            send('[API Monitor] Cannot find ' + clazz + '.' + method);
            return
        }
        var overloadCount = toHook.overloads.length;
        for (var i = 0; i < overloadCount; i++) {
            toHook.overloads[i].implementation = function () {
                var arguments_re={};
                try {
                    arguments_re = isArguments(api, arguments);
                } catch (err) {
                    send('[API Monitor] isArguments is err: ' + clazz + '.' + method + " [\"Error\"] => " + err);
                }
                var argz = [].slice.call(arguments);
                // send('[API Monitor] isArguments : ' + clazz + '.' + method + ", arg:" + argz + ", arguments_re: " + JSON.stringify(arguments_re) );
                // Call original function
                try {
                    var retval = this[method].apply(this, arguments);
                } catch (err) {
                    send('[API Monitor] apply err: ' + clazz + '.' + method + " [\"Error\"] => " + err);
                }
                if (!(api.only_severity && !arguments_re.severity_is) && callback) {
                    var calledFrom = Exception.$new().getStackTrace().toString().split(',')[1];
                    var message = {
                        name: name,
                        class: clazz,
                        method: method,
                        arguments: argz,
                        result: retval ? retval.toString() : null,
                        calledFrom: calledFrom
                    };
                    if (tag){
                       message.tag = tag;
                    }
                    if (arguments_re.severity_is) {
                        message.severity = arguments_re.severity;
                        message.severity_msg = arguments_re.severity_msg;
                        if (arguments_re.tag) {
                            message.tag = arguments_re.tag;
                        }
                    }
                    retval = callback(retval, message);
                }
                return retval;
            }
        }
    } catch (err) {
        send('[API Monitor] - ERROR: ' + clazz + "." + method + " [\"Error\"] => " + err);
    }
}


Java.performNow(function () {
    apis.forEach(function (api, _) {
        hook(api, function (originalResult, message) {
            /*if (!message.name.includes('Database') &&
                !message.name.includes('Crypto - Hash') &&
                !message.name.includes('File IO - Shared Preferences') &&
                !message.name.includes('File IO') &&
                !message.name.includes('IPC')) {
            */
            message.returnValue = originalResult
            if (originalResult && typeof originalResult === 'object') {
                var s = [];
                for (var k = 0, l = originalResult.length; k < l; k++) {
                    s.push(originalResult[k]);
                }
                message.returnValue = '' + s.join('');
            }
            if (!message.result)
                message.result = undefined
            if (!message.returnValue)
                message.returnValue = undefined
            var msg = 'MobSF-API-Monitor: ' + JSON.stringify(message);
            send(msg + ',');
            return originalResult;
        });
    });
});
