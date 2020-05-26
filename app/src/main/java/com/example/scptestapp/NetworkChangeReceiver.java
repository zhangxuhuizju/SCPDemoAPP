package com.example.scptestapp;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.widget.Toast;

import java.util.Objects;

public class NetworkChangeReceiver extends BroadcastReceiver {
    static {
        System.loadLibrary("native-lib");
    }
    private NetworkInfo lastConnectedNetwork;

    @Override
    public void onReceive(Context context, Intent intent) {
        System.out.println(System.currentTimeMillis());
        if (!isNetworkConnected(context)) {
            netClosed();
            return;
        }
        Toast.makeText(context, "changeNetwork!", Toast.LENGTH_LONG);
        //有连接的时候触发，加上判断逻辑
        System.out.println("Network Changed!");
        reset();
    }

//    public boolean networkStateChange(Context context) {
//        NetworkInfo networkInfo = ((ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE)).getActiveNetworkInfo();
//
//        if (networkInfo != null && networkInfo.getState() == NetworkInfo.State.CONNECTED) {
//            if (lastConnectedNetwork == null
//                    || lastConnectedNetwork.getType() != networkInfo.getType()
//                    || !equalsObj(lastConnectedNetwork.getExtraInfo(), networkInfo.getExtraInfo())
//            ) {
//
//                lastConnectedNetwork = networkInfo;
//                return true;
//            }
//        } else if (networkInfo == null) {
//            // Not connected, stop openvpn, set last connected network to no network
//            lastConnectedNetwork = null;
//            return false;
//        }
//        return false;
//    }
//
//        public static boolean equalsObj(Object a, Object b) {
//            return Objects.equals(a, b);
//        }


    public static boolean isNetworkConnected(Context context) {
        ConnectivityManager connectivity = (ConnectivityManager)context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (connectivity == null)
        {
            return false;
        }
        else {
            NetworkInfo[] info = connectivity.getAllNetworkInfo();
            if (info != null) {
                for (int i = 0; i < info.length; i++) {
                    if (info[i].getState() == NetworkInfo.State.CONNECTED) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private native void reset();
    private native void netClosed();
}
