package me.tippie.velocityauth;

import com.velocitypowered.api.event.EventTask;
import com.velocitypowered.api.event.ResultedEvent;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.command.CommandExecuteEvent;
import com.velocitypowered.api.event.player.PlayerChatEvent;
import com.velocitypowered.api.event.player.PlayerChooseInitialServerEvent;
import com.velocitypowered.api.event.player.ServerConnectedEvent;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import com.velocitypowered.api.scheduler.Scheduler;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.TextComponent;
import net.kyori.adventure.text.event.ClickEvent;
import net.kyori.adventure.text.event.HoverEvent;
import net.kyori.adventure.text.format.Style;
import net.kyori.adventure.text.format.TextColor;
import net.kyori.adventure.text.format.TextDecoration;
import ninja.leaping.configurate.ConfigurationNode;
import org.jetbrains.annotations.Nullable;

import java.net.InetSocketAddress;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

public class AuthManager {
    private final Set<Player> unauthenticated = new HashSet<>();

    @Nullable
    private final RegisteredServer hubServer;

    public AuthManager(ConfigurationNode node) {
        this.hubServer = VelocityAuth.getInstance().getServer().getServer(node.getNode("hub-server").getString()).orElse(null);
    }

    public boolean needsAuth(Player player) {
        return unauthenticated.contains(player);
    }

    public void authenticate(Player player) {
        unauthenticated.remove(player);
        VelocityAuth.getInstance().getStorage().setLastAddress(player.getUniqueId(), player.getRemoteAddress().getAddress());
    }

    @Subscribe
    public void onJoin(PlayerChooseInitialServerEvent event) {
        if (event.getPlayer().hasPermission("velocityauth.use")) {
            unauthenticated.add(event.getPlayer());

            VelocityAuth.getInstance().getStorage().isLastAddress(event.getPlayer().getUniqueId(), event.getPlayer().getRemoteAddress().getAddress()).thenAccept(isLastAddress -> {
                if (isLastAddress) {
                    unauthenticated.remove(event.getPlayer());
                    event.getPlayer().sendMessage(
                            Component.text("You are already authenticated as you have connected from the same IP address as last time.")
                                    .color(TextColor.color(0x999999))
                    );
                } else {
                    List<AuthStorage.Authenticator> authenticators = VelocityAuth.getInstance().getStorage().getAuthenticators(event.getPlayer().getUniqueId()).join();
                    if (authenticators.size() > 0) {
                        event.getPlayer().sendMessage(unauthenticatedMessage());
                    } else {
                        event.getPlayer().sendMessage(registerMessage());
                    }
                }
            });


        }
    }

    @Subscribe
    public void onChat(PlayerChatEvent event) {
        if (needsAuth(event.getPlayer())) {
            event.getPlayer().disconnect(Component.text("You need to authenticate using /auth before doing anything else!"));
            event.setResult(PlayerChatEvent.ChatResult.denied());
        }
    }

    @Subscribe
    public void onCommand(CommandExecuteEvent event) {
        if (event.getCommand().toLowerCase().startsWith("auth")) return;
        if (event.getCommandSource() instanceof Player player && this.needsAuth(player)) {
            player.disconnect(Component.text("You need to authenticate using /auth before doing anything else!"));
            event.setResult(CommandExecuteEvent.CommandResult.denied());
        }
    }

    @Subscribe
    public void onServerChange(ServerConnectedEvent event) {
        if (this.needsAuth(event.getPlayer()) && !event.getServer().equals(hubServer)) {
            event.getPlayer().sendMessage(unauthenticatedMessage());
            VelocityAuth.getInstance().getServer().getScheduler().buildTask(VelocityAuth.getInstance(), () -> {
                event.getPlayer().createConnectionRequest(hubServer).fireAndForget();
            }).delay(500, TimeUnit.MILLISECONDS).schedule();
        }
    }

    private static TextComponent registerMessage() {
        TextComponent message = Component.text("\nYou need to authenticate before you can join the server.\n")
                .color(TextColor.color(0x999999));

        Style buttonStyle = Style.style()
                .color(TextColor.color(0xFFBE))
                .build();

        TextComponent registerYubikey = Component.text("[Register Yubikey]\n")
                .style(buttonStyle)
                .hoverEvent(HoverEvent.showText(Component.text("Click to register a Yubikey as your second factor.")))
                .clickEvent(ClickEvent.runCommand("/auth register YUBIKEY_OTP"));

        TextComponent registerTOTP = Component.text("[Register Time Based OTP]\n")
                .style(buttonStyle)
                .hoverEvent(HoverEvent.showText(Component.text("Click to register a Time Based OTP as your second factor.")))
                .clickEvent(ClickEvent.runCommand("/auth register TIMEBASED_OTP"));

        TextComponent registerAlt = Component.text("[Register As Alternate Account]\n")
                .style(buttonStyle.color(TextColor.color(0xA6FF)))
                .hoverEvent(HoverEvent.showText(Component.text("Click to register this account as an alternate account as your second factor.")))
                .clickEvent(ClickEvent.runCommand("/auth register ALT"));

        return message.append(registerYubikey).append(registerTOTP).append(registerAlt);
    }

    private static TextComponent unauthenticatedMessage() {
        return Component.text("\nPlease enter your authentication code using ").color(TextColor.color(0x999999))
                .append(Component.text("/auth <code>").color(TextColor.color(0xFFBE))).clickEvent(ClickEvent.suggestCommand("/auth "))
                .append(Component.text(" to authenticate\n").color(TextColor.color(0x999999)));
    }
}
