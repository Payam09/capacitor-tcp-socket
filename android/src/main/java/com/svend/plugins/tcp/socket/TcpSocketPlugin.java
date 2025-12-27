package com.svend.plugins.tcp.socket;

import android.Manifest;
import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.os.Build;
import android.util.Log;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;
import com.getcapacitor.annotation.Permission;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

@CapacitorPlugin(name = "TcpSocket", permissions = {
        @Permission(
                alias = "network",
                strings = {Manifest.permission.ACCESS_NETWORK_STATE}
        )
})
public class TcpSocketPlugin extends Plugin {

    private Socket socket;
    private DataOutputStream mBufferOut;
    private List<Socket> clients = new ArrayList<>();
    private Network currentNetwork;
    private ConnectivityManager.NetworkCallback networkCallback;

    @PluginMethod()
    public void connect(PluginCall call) {
        String ipAddress = call.getString("ipAddress");
        if (ipAddress == null || ipAddress.isEmpty()) {
            call.reject("Must provide ip address to connect");
            return;
        }
        Integer port = call.getInt("port", 9100);
        Integer timeout = call.getInt("timeout", 10);

        ConnectivityManager connectivityManager = (ConnectivityManager) getContext().getSystemService(Context.CONNECTIVITY_SERVICE);
        if (connectivityManager == null) {
            call.reject("ConnectivityManager not available");
            return;
        }

        try {
            // 清理现有连接
            if (socket != null) {
                try {
                    socket.close();
                } catch (IOException ignored) {}
            }
            if (networkCallback != null) {
                try {
                    connectivityManager.unregisterNetworkCallback(networkCallback);
                } catch (Exception ignored) {}
                networkCallback = null;
            }

            // 获取或请求 Wi-Fi Network
            Network[] networks = connectivityManager.getAllNetworks();
            for (Network network : networks) {
                NetworkCapabilities caps = connectivityManager.getNetworkCapabilities(network);
                if (caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                    currentNetwork = network;
                    break;
                }
            }

            if (currentNetwork == null) {
                NetworkRequest networkRequest = new NetworkRequest.Builder()
                        .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                        .removeCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                        .build();

                networkCallback = new ConnectivityManager.NetworkCallback() {
                    @Override
                    public void onAvailable(Network network) {
                        currentNetwork = network;
                    }

                    @Override
                    public void onLost(Network network) {
                        try {
                            if (socket != null) socket.close();
                        } catch (IOException ignored) {}
                        socket = null;
                        currentNetwork = null;
                    }
                };

                connectivityManager.requestNetwork(networkRequest, networkCallback);

                long startTime = System.currentTimeMillis();
                while (currentNetwork == null && (System.currentTimeMillis() - startTime) < timeout * 1000) {
                    try {
                        Thread.sleep(100);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        call.reject("Network request interrupted");
                        return;
                    }
                }

                if (currentNetwork == null) {
                    call.reject("Wi-Fi network not available within timeout");
                    return;
                }
            }

            // 绑定进程到 Network，创建并连接 Socket
            boolean wasBound = false;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                try {
                    connectivityManager.bindProcessToNetwork(currentNetwork);
                    wasBound = true;
                } catch (Exception e) {
                    Log.w("TcpSocket", "Failed to bind process to network", e);
                }
            }

            try {
                // 解析并验证 IPv4
                InetAddress inetAddress = InetAddress.getByName(ipAddress);
                if (!(inetAddress instanceof Inet4Address)) {
                    call.reject("IP address must be IPv4");
                    return;
                }

                // 通过 Network 创建 Socket
                socket = currentNetwork.getSocketFactory().createSocket();
                socket.setKeepAlive(true);
                socket.setTcpNoDelay(true);
                socket.setSoTimeout(timeout * 1000);
                socket.connect(new InetSocketAddress(inetAddress, port), timeout * 1000);
                clients.add(socket);
            } finally {
                // 解绑进程
                if (wasBound && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    try {
                        connectivityManager.bindProcessToNetwork(null);
                    } catch (Exception ignored) {}
                }
            }
    
            JSObject ret = new JSObject();
            ret.put("client", clients.size() - 1);
            call.resolve(ret);
    
        } catch (Exception e) {
            Log.e("TcpSocket", "Connection failed", e);
            if (socket != null) {
                try {
                    socket.close();
                } catch (IOException ignored) {}
                socket = null;
            }
            call.reject(e.getMessage());
        }
    }

    @PluginMethod()
    public void send(final PluginCall call) {
        final Integer client = call.getInt("client", -1);
        final String msg = call.getString("data", "");

        if (client == -1) {
            call.reject("No client specified");
            return;
        }

        Runnable runnable = () -> {
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    final Socket socket = clients.get(client);
                    mBufferOut = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));
                    byte[] decoded = Base64.getDecoder().decode(msg);
                    if (mBufferOut != null) {
                        mBufferOut.write(decoded);
                        mBufferOut.flush();
                    }
                }
                call.resolve();
            } catch (IOException e) {
                call.reject(e.getMessage());
            }
        };

        Socket socket = clients.get(client);
        if (!socket.isConnected()) {
            try {
                socket.close();
            } catch (IOException e) {
                call.reject("Generic error");
            }
            call.reject("Socket not connected");
            return;
        }
        Thread thread = new Thread(runnable);
        thread.start();
    }

    @PluginMethod()
    public void read(final PluginCall call) {
        final Integer client = call.getInt("client", -1);
        final Integer length = call.getInt("expectLen", 1024);
        final Integer timeout = call.getInt("timeout", 30);

        if (client == -1) {
            call.reject("Client not specified");
            return;
        }

        new Thread(() -> {
            try {
                Socket socket;
                synchronized (clients) {
                    if (client >= clients.size() || (socket = clients.get(client)) == null) {
                        call.reject("Invalid client ID");
                        return;
                    }
                }

                if (socket.isClosed() || !socket.isConnected()) {
                    call.reject("Socket not connected");
                    return;
                }

                // 如果提供了超时参数，更新超时设置（connect 时已设置默认值）
                if (timeout != null && timeout > 0) {
                    socket.setSoTimeout(timeout * 1000);
                }

                java.io.InputStream inputStream = socket.getInputStream();
                
                // 直接读取数据，read() 会在超时范围内等待数据到达
                // available() 只返回当前缓冲区数据，不能用于判断是否有数据在传输中
                byte[] bytes = new byte[length];
                int bytesRead = inputStream.read(bytes, 0, length);

                JSObject ret = new JSObject();
                if (bytesRead > 0) {
                    // 只在需要时复制数组（性能优化）
                    if (bytesRead == length) {
                        ret.put("result", Base64.getEncoder().encodeToString(bytes));
                    } else {
                        ret.put("result", Base64.getEncoder().encodeToString(Arrays.copyOf(bytes, bytesRead)));
                    }
                } else {
                    ret.put("result", "");
                }
                call.resolve(ret);
            } catch (java.net.SocketTimeoutException e) {
                JSObject ret = new JSObject();
                ret.put("result", "");
                call.resolve(ret);
            } catch (IOException e) {
                call.reject(e.getMessage());
            }
        }).start();
    }

    @PluginMethod()
    public void disconnect(PluginCall call) {
        final Integer client = call.getInt("client", -1);
        if (client == -1) {
            call.reject("No client specified");
            return;
        }
        if (clients.isEmpty()) {
            call.reject("Socket not connected");
            return;
        }
        final Socket socket = clients.get(client);
        try {
            if (!socket.isConnected()) {
                socket.close();
                call.reject("Socket not connected");
            }
            socket.close();
        } catch (IOException e) {
            call.reject(e.getMessage());
        }

        // 注销 NetworkCallback
        if (networkCallback != null) {
            try {
                ConnectivityManager cm = (ConnectivityManager) getContext().getSystemService(Context.CONNECTIVITY_SERVICE);
                if (cm != null) {
                    cm.unregisterNetworkCallback(networkCallback);
                }
            } catch (Exception e) {
                Log.e("TcpSocket", "Error unregistering network callback", e);
            }
            networkCallback = null;
        }
        currentNetwork = null;

        JSObject ret = new JSObject();
        ret.put("client", client);
        call.resolve(ret);
    }
}
