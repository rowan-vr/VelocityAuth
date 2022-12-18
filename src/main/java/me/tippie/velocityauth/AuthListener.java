package me.tippie.velocityauth;

import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.command.CommandExecuteEvent;
import com.velocitypowered.api.event.player.PlayerChatEvent;
import com.velocitypowered.api.event.player.ServerConnectedEvent;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import ninja.leaping.configurate.ConfigurationNode;

public class AuthListener {

    private final AuthManager manager;
    private RegisteredServer hubServer;

    public AuthListener(AuthManager manager, ConfigurationNode node){
        this.manager = manager;
        this.hubServer =  node.getNode("hub-server").getString();
        HashMap
    }

    @Subscribe
    public void onChat(PlayerChatEvent event){
        if (manager.needsAuth(event.getPlayer())){
            event.setResult(PlayerChatEvent.ChatResult.denied());
        }
    }

    @Subscribe
    public void onCommand(CommandExecuteEvent event){
        if (event.getCommandSource() instanceof Player player && manager.needsAuth(player)){
            event.setResult(CommandExecuteEvent.CommandResult.denied());
        }
    }

    @Subscribe
    public void onServerChange(ServerConnectedEvent event){
        if (manager.needsAuth(event.getPlayer()) && !event.getServer().getServerInfo().getName().equalsIgnoreCase(hubServer)){
            event.getPlayer().createConnectionRequest()
        }
    }
}
