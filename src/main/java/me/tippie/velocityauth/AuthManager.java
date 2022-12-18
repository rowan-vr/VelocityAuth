package me.tippie.velocityauth;

import com.velocitypowered.api.event.EventTask;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.player.PlayerChooseInitialServerEvent;
import com.velocitypowered.api.proxy.Player;

import java.util.HashSet;
import java.util.Set;

public class AuthManager {
    private final Set<Player> unauthenticated = new HashSet<>();


    public boolean needsAuth(Player player){
        return unauthenticated.contains(player);
    }

    @Subscribe
    public void onJoin(PlayerChooseInitialServerEvent event){
        if(event.getPlayer().hasPermission("velocityauth.use")){
            unauthenticated.add(event.getPlayer());

            EventTask.async(()->{
               //TODO: Check IP
            });
        }
    }
}
