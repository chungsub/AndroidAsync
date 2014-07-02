package com.koushikdutta.async.sample;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.logging.Logger;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateFactory;

import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;
import org.json.JSONArray;
import org.json.JSONObject;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.drawable.BitmapDrawable;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.MenuItem.OnMenuItemClickListener;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.Toast;

import com.koushikdutta.async.http.*;
import com.koushikdutta.async.http.body.UrlEncodedFormBody;
import com.koushikdutta.async.http.socketio.*;

public class MainActivity extends Activity {
    static ResponseCacheMiddleware cacher; 

	/**
	 * tag and log
	 */
	private static final String TAG = "SocketIo";
	private static final boolean DEBUG_LOG = true;
    
    ImageView rommanager;
    ImageView tether;
    ImageView desksms;
    ImageView chart;

	private SocketIOClient mSocketIOClient;


    @SuppressLint("NewApi")
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        if (cacher == null) {
            try {
                cacher = ResponseCacheMiddleware.addCache(AsyncHttpClient.getDefaultInstance(), getFileStreamPath("asynccache"), 1024 * 1024 * 10);
                cacher.setCaching(false);
            }
            catch (IOException e) {
                Toast.makeText(getApplicationContext(), "unable to create cache", Toast.LENGTH_SHORT).show();
            }
        }
        setContentView(R.layout.activity_main);
        
        Button b = (Button)findViewById(R.id.go);
        b.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View v) {
                //refresh();
                testSocketIO();
            }
        });
        
        rommanager = (ImageView)findViewById(R.id.rommanager);
        tether = (ImageView)findViewById(R.id.tether);
        desksms = (ImageView)findViewById(R.id.desksms);
        chart = (ImageView)findViewById(R.id.chart);
        
        showCacheToast();
    }

    void showCacheToast() {
        boolean caching = cacher.getCaching();
        Toast.makeText(getApplicationContext(), "Caching: " + caching, Toast.LENGTH_SHORT).show();
    }
    
    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        menu.add("Toggle Caching").setOnMenuItemClickListener(new OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                cacher.setCaching(!cacher.getCaching());
                showCacheToast();
                return true;
            }
        });
        return true;
    }

    private void getFile(final ImageView iv, String url, final String filename) {
        AsyncHttpClient.getDefaultInstance().executeFile(new AsyncHttpGet(url), filename, new AsyncHttpClient.FileCallback() {
            @Override
            public void onCompleted(Exception e, AsyncHttpResponse response, File result) {
                if (e != null) {
                    e.printStackTrace();
                    return;
                }
                Bitmap bitmap = BitmapFactory.decodeFile(filename);
                result.delete();
                if (bitmap == null)
                    return;
                BitmapDrawable bd = new BitmapDrawable(bitmap);
                iv.setImageDrawable(bd);
            }
        });
    }

    private void getChartFile() {
        final ImageView iv = chart;
        final String filename = getFileStreamPath(randomFile()).getAbsolutePath();
        ArrayList<NameValuePair> pairs = new ArrayList<NameValuePair>();
        pairs.add(new BasicNameValuePair("cht", "lc"));
        pairs.add(new BasicNameValuePair("chtt", "This is a google chart"));
        pairs.add(new BasicNameValuePair("chs", "512x512"));
        pairs.add(new BasicNameValuePair("chxt", "x"));
        pairs.add(new BasicNameValuePair("chd", "t:40,20,50,20,100"));
        UrlEncodedFormBody writer = new UrlEncodedFormBody(pairs);
        try {
            AsyncHttpPost post = new AsyncHttpPost("http://chart.googleapis.com/chart");
            post.setBody(writer);
            AsyncHttpClient.getDefaultInstance().executeFile(post, filename, new AsyncHttpClient.FileCallback() {
                @Override
                public void onCompleted(Exception e, AsyncHttpResponse response, File result) {
                    if (e != null) {
                        e.printStackTrace();
                        return;
                    }
                    Bitmap bitmap = BitmapFactory.decodeFile(filename);
                    result.delete();
                    if (bitmap == null)
                        return;
                    BitmapDrawable bd = new BitmapDrawable(bitmap);
                    iv.setImageDrawable(bd);
                }
            });
        }
        catch (Exception ex) {
            ex.printStackTrace();
        }
    }
    
    private String randomFile() {
        return ((Long)Math.round(Math.random() * 1000)).toString() + ".png";
    }

    private void prepareSSL() 
    {
        Certificate ca = null;
        InputStream caInput = null;

		try {
            // Load CAs from an InputStream
            // (could be from a resource or ByteArrayInputStream or ...)
            CertificateFactory cf;
            
			cf = CertificateFactory.getInstance("X.509");
            
            // From https://www.washington.edu/itconnect/security/ca/load-der.crt
            //InputStream caInput = new BufferedInputStream(new FileInputStream("ComodoUTNSGCCA.crt"));
            caInput = getResources().openRawResource(com.koushikdutta.async.sample.R.raw.comodoutnsgcca);

            ca = cf.generateCertificate(caInput);
            Log.v(TAG, "ca=" + ((X509Certificate) ca).getSubjectDN());

            // Create a KeyStore containing our trusted CAs
            String keyStoreType = KeyStore.getDefaultType();
            KeyStore keyStore = KeyStore.getInstance(keyStoreType);
            keyStore.load(null, null);
            keyStore.setCertificateEntry("ca", ca);
            
            // Create a TrustManager that trusts the CAs in our KeyStore
            String tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
            tmf.init(keyStore);
            
            // Create an SSLContext that uses our TrustManager
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, tmf.getTrustManagers(), null);
            
            AsyncHttpClient.getDefaultInstance().getSSLSocketMiddleware().setSSLContext(context);
            AsyncHttpClient.getDefaultInstance().getSSLSocketMiddleware().setTrustManagers(tmf.getTrustManagers());
		} 
		catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
        catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
        catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
        catch (KeyManagementException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
        catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        finally {
            if (caInput != null) {
                try {
					caInput.close();
				} 
                catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
            }
        }

        // Tell the URLConnection to use a SocketFactory from our SSLContext
        /*
        URL url = new URL("https://certs.cac.washington.edu/CAtest/");
        HttpsURLConnection urlConnection =
            (HttpsURLConnection)url.openConnection();
        urlConnection.setSSLSocketFactory(context.getSocketFactory());
        InputStream in = urlConnection.getInputStream();
        copyInputStreamToOutputStream(in, System.out);
        */
    
        /*    
        try {
            String storepass = "abcdef";
            
            //KeyManagerFactory kmf = KeyManagerFactory.getInstance("X509");
            //KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            
            //ks.load(getContext().getResources().openRawResource(R.raw.keystore), storepass.toCharArray());
            //kmf.init(ks, storepass.toCharArray());
            
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            //KeyStore ts = KeyStore.getInstance(KeyStore.getDefaultType());
            KeyStore ts = KeyStore.getInstance("BKS");
            ts.load(getResources().openRawResource(com.koushikdutta.async.sample.R.raw.keystore), storepass.toCharArray());
            tmf.init(ts);
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            //sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            //sslContext.init(null, tmf.getTrustManagers(), null);
            sslContext.init(null, null, null);
            
            AsyncHttpClient.getDefaultInstance().getSSLSocketMiddleware().setSSLContext(sslContext);
            AsyncHttpClient.getDefaultInstance().getSSLSocketMiddleware().setTrustManagers(tmf.getTrustManagers());
        }
        catch (CertificateException ce) {
            Log.e(TAG, "CertificateException occurred");
        }
        catch (IOException ioe) {
            Log.e(TAG, "IOException occurred");
            ioe.printStackTrace();
        }
        catch (KeyManagementException kme) {
            Log.e(TAG, "KeyManagementException occurred");            
        }
        catch (KeyStoreException kse) {
            Log.e(TAG, "KeyStoreException occurred");
        }
        catch (NoSuchAlgorithmException nsae) {
            Log.e(TAG, "NoSuchAlgorithmException occurred");
        }
        finally {
        }
        */        
    }

    private void trustAllHosts() {
        // HostnameVerifier hostnameVerifier =
        // org.apache.http.conn.ssl.SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;
        HostnameVerifier hostnameVerifier = new HostnameVerifier() {

            @Override
            public boolean verify(String hostname, SSLSession session) {
                Log.v(TAG, "Verifying " + hostname);
                return true;
            }
        };

        AsyncSSLSocketMiddleware sslm = AsyncHttpClient.getDefaultInstance().getSSLSocketMiddleware();
        sslm.setHostnameVerifier(hostnameVerifier);

        // Create a trust manager that does not validate certificate chains
        TrustManager[] trustAllCerts = new TrustManager[] { 
            new X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                    return new java.security.cert.X509Certificate[] {};
                }

                @Override
                public void checkClientTrusted(
                        java.security.cert.X509Certificate[] chain, String authType)
                        throws java.security.cert.CertificateException {
                    // TODO Auto-generated method stub

                }

                @Override
                public void checkServerTrusted(
                        java.security.cert.X509Certificate[] chain, String authType)
                        throws java.security.cert.CertificateException {
                    // TODO Auto-generated method stub

                }
            } 
        };

        sslm.setTrustManagers(trustAllCerts);

        // Install the all-trusting trust manager
        try {
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            sslm.setSSLContext(sc);
//          HttpsURLConnection
//                  .setDefaultSSLSocketFactory(sc.getSocketFactory());
        } 
        catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void disconnect()
    {
        if (mSocketIOClient != null) {
            mSocketIOClient.disconnect();
        }
    }

    private void testSocketIO()
    {
		String serverAddr = "https://172.16.0.103";
		//String serverAddr = "https://vod.writingand.com";

        String email = "john.doe@example.com";
        String passwd = "takedown";
        String endpoint = "/api";
        
		// String uri;
		String query;
		try {
			query = "app=true&email=" + URLEncoder.encode(email, "UTF-8") + "&password=" + URLEncoder.encode(passwd, "UTF-8");
            //query = "email=" + URLEncoder.encode(email, "UTF-8") + "&password=" + URLEncoder.encode(passwd, "UTF-8");
		} 
        catch (UnsupportedEncodingException e1) {
			e1.printStackTrace();
			Log.e(TAG, "Could not make the uri for connection: (email:" + email + ",passwd:" + passwd + ")");
			return;
		}

		trustAllHosts();
		//prepareSSL();

		// prepare socket.io client
		// TODO: SHOULD BE SECURED!!!

		//AsyncHttpClient client = AsyncHttpClient.getDefaultInstance();
		SocketIORequest sioreq = new SocketIORequest(serverAddr, "", query);
		//SocketIORequest sioreq = new SocketIORequest(serverAddr, "", "");

        final String final_endpoint = endpoint;
        final String final_query = query;

        ConnectCallback connectCallback = new ConnectCallback() {
            public void onConnectCompleted(Exception ex, SocketIOClient client) {
                if (ex != null) {
                    // SHOULD ARRIVE WHEN CONNECTING TO GLOBAL NAMESPACE FAILS
                    Log.v(TAG, "failed to connecting to global namespace");
                    Log.v(TAG, "exception occurred");

                    String exMessage = ex.getMessage();
                    if (TextUtils.equals(exMessage, "handshake bad origin") ||
                        TextUtils.equals(exMessage, "handshake error") ||
                        TextUtils.equals(exMessage, "handshake unauthorized")) {
                        // An error occurred during authorization step
                        Log.v(TAG, exMessage);
                    }

                    return;
                }

                Log.e(TAG, "onConnectCompleted");

                mSocketIOClient = client;

                final SocketIOClient final_client = client;

                client.setErrorCallback(new ErrorCallback() {
                    public void onError(String error) {
                        Log.e(TAG, "error on 1st stage");
                        Log.e(TAG, "error: " + error);

                        //final_client.disconnect();
                        //client.disconnect();
                        //disconnect();
                    }
                });
                

                //client.of(final_endpoint, final_query, new ConnectCallback() {
                client.of(final_endpoint, new ConnectCallback() {
                    public void onConnectCompleted(Exception ex, SocketIOClient client) {
                        Log.e(TAG, "final stage of onConnectCompleted");

                        if (ex != null) {
                            Log.v(TAG, "exception occurred in " + final_endpoint);
                            ex.printStackTrace();
                            mSocketIOClient.disconnect();
                            return;
                        }
                        
                        mSocketIOClient = client;

                        final SocketIOClient final_client = client;
                        
                        client.setStringCallback(new StringCallback() {
                            public void onString(String string, Acknowledge acknowledge) {
                                System.out.println(string);
                            }
                        });
                        
                        client.setJSONCallback(new JSONCallback() {
                            public void onJSON(JSONObject json, Acknowledge acknowledge) {
                                System.out.println("json: " + json.toString());
                            }
                        });
                        
                        client.setErrorCallback(new ErrorCallback() {
                            public void onError(String error) {
                                Log.e(TAG, "error on 2nd stage");
                                Log.e(TAG, "error: " + error);

                                final_client.disconnect();
                            }
                        });
                    }
                });
            };

        };
    
        SocketIOClient.connect(AsyncHttpClient.getDefaultInstance(), sioreq, connectCallback);
    }
    
    private void refresh() {
        rommanager.setImageBitmap(null);
        tether.setImageBitmap(null);
        desksms.setImageBitmap(null);
        chart.setImageBitmap(null);
        
        getFile(rommanager, "https://raw.github.com/koush/AndroidAsync/master/rommanager.png", getFileStreamPath(randomFile()).getAbsolutePath());
        getFile(tether, "https://raw.github.com/koush/AndroidAsync/master/tether.png", getFileStreamPath(randomFile()).getAbsolutePath());
        getFile(desksms, "https://raw.github.com/koush/AndroidAsync/master/desksms.png", getFileStreamPath(randomFile()).getAbsolutePath());
        getChartFile();
        
        Log.i(LOGTAG, "cache hit: " + cacher.getCacheHitCount());
        Log.i(LOGTAG, "cache store: " + cacher.getCacheStoreCount());
        Log.i(LOGTAG, "conditional cache hit: " + cacher.getConditionalCacheHitCount());
        Log.i(LOGTAG, "network: " + cacher.getNetworkCount());
    }
    
    private static final String LOGTAG = "AsyncSample";
}

