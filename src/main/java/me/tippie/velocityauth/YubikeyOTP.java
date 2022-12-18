package me.tippie.velocityauth;

import org.asynchttpclient.AsyncHttpClient;
import org.asynchttpclient.Dsl;
import org.asynchttpclient.Response;

import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

public class YubikeyOTP {
    public static CompletableFuture<Boolean> verify(String otp, UUID id, boolean allowAll) {
        return CompletableFuture.supplyAsync(() -> {
            if (!allowAll && !VelocityAuth.getInstance().getStorage().getYubikeys(id).join().contains(getKeyFromOTP(otp)))
                return false;

            try (AsyncHttpClient client = Dsl.asyncHttpClient()) {
                String req = "https://api.yubico.com/wsapi/2.0/verify?otp="+otp+"&id=1&timeout=8&sl=50&nonce="+UUID.randomUUID().toString().replace("-","");
                Response response = client.prepareGet(req).execute().toCompletableFuture().join();
                return response.getStatusCode() == 200 && response.getResponseBody().contains("status=OK");
            } catch (Exception e) {
                e.printStackTrace();
                return false;
            }
        });
    }

    public static CompletableFuture<Boolean> verify(String otp, UUID id) {
        return verify(otp, id, false);
    }

    public static String getKeyFromOTP(String otp) {
        return otp.substring(0, 12);
    }
}
