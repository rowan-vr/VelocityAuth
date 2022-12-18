package me.tippie.velocityauth;

import com.j256.twofactorauth.TimeBasedOneTimePasswordUtil;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.TextComponent;
import net.kyori.adventure.text.event.ClickEvent;
import net.kyori.adventure.text.format.TextColor;
import net.kyori.adventure.text.format.TextDecoration;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.CompletableFuture;

public class AuthCommand implements SimpleCommand {

    private final HashMap<UUID, PendingRegistration> pendingRegistrations = new HashMap<>();
    private final HashMap<UUID, UUID> pendingAltAuthentications = new HashMap<>();

    @Override
    public void execute(Invocation invocation) {
        if (!invocation.source().hasPermission("velocityauth.use")) {
            invocation.source().sendMessage(Component.text("You do not have permission to use this command.").color(TextColor.color(0xFF7D6E)));
            return;
        }

        if (invocation.arguments().length == 0) {
            invocation.source().sendMessage(Component.text("\nCommand Usage ").color(TextColor.color(0xFF97))
                    .append(Component.text("/auth\n").color(TextColor.color(0xFFBE)))
                    .append(Component.text(" - ").color(TextColor.color(0x999999)).append(Component.text("/auth admin <subcommand>").color(TextColor.color(0x78fdff)))
                            .append(Component.text(": Administration commands for Velocity Auth\n").color(TextColor.color(0x999999)))
                    )
                    .append(Component.text(" - ").color(TextColor.color(0x999999)).append(Component.text("/auth manage").color(TextColor.color(0x78fdff)))
                            .append(Component.text(": Manage your own authenticators.\n").color(TextColor.color(0x999999)))
                    )
            );
            return;
        }

        Player player = (Player) invocation.source();

        if (pendingAltAuthentications.containsKey(player.getUniqueId()) && invocation.arguments().length == 1) {
            verify(player, invocation.arguments()[0]).thenAccept(result -> {
                if (result) {
                    Player other = VelocityAuth.getInstance().getServer().getPlayer(pendingAltAuthentications.remove(player.getUniqueId())).orElse(null);
                    if (other == null) return;
                    player.sendMessage(Component.text("Adding alternate account...").color(TextColor.color(0x999999)).decorate(TextDecoration.ITALIC));
                    other.sendMessage(Component.text("Adding alternate account...").color(TextColor.color(0x999999)).decorate(TextDecoration.ITALIC));
                    VelocityAuth.getInstance().getStorage().getAuthUser(player.getUniqueId()).thenAccept(authUser -> {
                        VelocityAuth.getInstance().getStorage().registerUser(other.getUniqueId(), authUser);
                        player.sendMessage(Component.text("Alternate account added!").color(TextColor.color(0x64FF9D)).decorate(TextDecoration.ITALIC));
                        other.sendMessage(Component.text("Alternate account added!").color(TextColor.color(0x64FF9D)).decorate(TextDecoration.ITALIC));
                    });
                } else {
                    player.sendMessage(Component.text("Invalid code!").color(TextColor.color(0xFF7D6E)));
                }
            });
            return;
        }

        if (pendingRegistrations.containsKey(player.getUniqueId()) && invocation.arguments().length == 1) {
            register(player, invocation.arguments()[0]);
            return;
        }

        AuthManager manager = VelocityAuth.getInstance().getManager();
        if (manager.needsAuth(player) && !invocation.arguments()[0].equalsIgnoreCase("register")) {
            invocation.source().sendMessage(Component.text("\nVerifying code...").color(TextColor.color(0x999999)).decorate(TextDecoration.ITALIC));
            verify(player, invocation.arguments()[0]).thenAccept((success) -> {
                if (success) {
                    manager.authenticate(player);
                    player.sendMessage(Component.text("Successfully authenticated!\n").color(TextColor.color(0x64FF9D)));
                } else {
                    player.sendMessage(Component.text("Invalid code!\n").color(TextColor.color(0xFF7D6E)));
                }
            });
            return;
        }


        switch (invocation.arguments()[0].toLowerCase()) {
            case "register" -> {
                if (invocation.arguments().length < 2) return;
                String type = invocation.arguments()[1];

                if (type.equals("ALT") && invocation.arguments().length == 2) {
                    player.sendMessage(Component.text("Please enter your other accounts username using ").color(TextColor.color(0x999999))
                            .append(Component.text("/auth register ALT <username>").color(TextColor.color(0xFFBE))
                                    .clickEvent(ClickEvent.suggestCommand("/auth register ALT "))));
                    return;
                } else if (type.equals("ALT") && invocation.arguments().length == 3) {
                    VelocityAuth.getInstance().getStorage().isRegistered(player.getUniqueId()).thenAccept((isRegistered) -> {
                        if (isRegistered) {
                            player.sendMessage(Component.text("You are already registered!").color(TextColor.color(0xFF7D6E)));
                            return;
                        }
                        Player other = VelocityAuth.getInstance().getServer().getPlayer(invocation.arguments()[2]).orElse(null);
                        if (other == null) {
                            player.sendMessage(Component.text("This player could not be found on this proxy server.").color(TextColor.color(0xFF7D6E)));
                            return;
                        } else if (other.getUniqueId().equals(player.getUniqueId())) {
                            player.sendMessage(Component.text("You cannot add yourself as an alternate account.").color(TextColor.color(0xFF7D6E)));
                            return;
                        } else if (VelocityAuth.getInstance().getStorage().getAuthUser(other.getUniqueId()).join() == -1) {
                            player.sendMessage(Component.text("This player is not registered.").color(TextColor.color(0xFF7D6E)));
                            return;
                        }

                        pendingAltAuthentications.put(other.getUniqueId(), player.getUniqueId());
                        player.sendMessage(Component.text("Please enter the authentication code of your other account using ").color(TextColor.color(0x999999))
                                .append(Component.text("/auth [code]").color(TextColor.color(0xFFBE))
                                        .clickEvent(ClickEvent.suggestCommand("/auth ")))
                                .append(Component.text(" on ").color(TextColor.color(0x999999)))
                                .append(Component.text(other.getUsername()).color(TextColor.color(0xFFBE)))
                                .append(Component.text(" to finish registration")).color(TextColor.color(0x999999))
                        );
                    });

                    return;
                }

                if (Arrays.stream(AuthenticatorType.values()).noneMatch(t -> t.toString().equals(type))) return;

                if (type.equals("YUBIKEY_OTP")) {
                    pendingRegistrations.put(player.getUniqueId(), new PendingRegistration(AuthenticatorType.YUBIKEY_OTP, null));
                    player.sendMessage(Component.text("Please run the following command ").color(TextColor.color(0x999999))
                            .append(Component.text("/auth [code]").color(TextColor.color(0xFFBE)).clickEvent(ClickEvent.suggestCommand("/auth ")))
                            .append(Component.text(" to finish registration.").color(TextColor.color(0x999999)))
                    );
                } else if (type.equals("TIMEBASED_OTP")) {
                    VelocityAuth.getInstance().getStorage().hasTimeBasedOTP(player.getUniqueId()).thenAccept((hasTimeBasedOTP) -> {
                        if (hasTimeBasedOTP) {
                            player.sendMessage(Component.text("You already have a time based authenticator registered!").color(TextColor.color(0xFF7D6E)));
                        } else {
                            String secret = TimeBasedOneTimePasswordUtil.generateBase32Secret();
                            pendingRegistrations.put(player.getUniqueId(), new PendingRegistration(AuthenticatorType.TIMEBASED_OTP, secret));
                            String serverName = null;
                            try {
                                serverName = URLEncoder.encode(VelocityAuth.getInstance().getConfiguration().getNode("server-name").getString("Cool Network"), StandardCharsets.UTF_8.toString());
                            } catch (UnsupportedEncodingException e) {
                                VelocityAuth.getInstance().getLogger().warn("Could not encode server name!");
                                serverName = "minecraftserver";
                            }
                            String image = TimeBasedOneTimePasswordUtil.qrImageUrl(serverName, secret);
                            image = image.replace("|", "%0A%7C");
                            player.sendMessage(Component.text("Please scan the following QR ").color(TextColor.color(0x999999))
                                    .append(Component.text("[Click here]").color(TextColor.color(0xFFBE)).clickEvent(ClickEvent.openUrl(image)))
                                    .append(Component.text(" with your authenticator app and run ").color(TextColor.color(0x999999)))
                                    .append(Component.text("/auth [code]").color(TextColor.color(0xFFBE)).clickEvent(ClickEvent.suggestCommand("/auth ")))
                                    .append(Component.text(" to finish registration.").color(TextColor.color(0x999999)))
                            );
                        }
                    });

                }
            }
            case "manage" -> {
                VelocityAuth.getInstance().getStorage().getAuthenticators(player.getUniqueId()).thenAccept(authenticators -> {
                    if (invocation.arguments().length == 2 && invocation.arguments()[1].equalsIgnoreCase("yubikeys")) {
                        player.sendMessage(Component.text("\nYour Yubikeys:\n").color(TextColor.color(0xFFBE)));
                        authenticators.stream().filter(authenticator -> authenticator.type() == AuthenticatorType.YUBIKEY_OTP).forEach(authenticator -> {
                            player.sendMessage(Component.text(" - ").color(TextColor.color(0x999999))
                                            .append(Component.text(authenticator.secret()).color(TextColor.color(0x78fdff)))
//                                    .append(Component.text(" - ").color(TextColor.color(0x999999)))
                                            .append(Component.text(" [Remove Key]").color(TextColor.color(0xbd261e)).clickEvent(ClickEvent.runCommand("/auth remove yubikey " + authenticator.secret())))
                            );
                        });
                    } else {
                        player.sendMessage(Component.text("\nYour authenticators:\n").color(TextColor.color(0xFFBE)));

                        boolean hasTimeBasedOTP = authenticators.stream().anyMatch(authenticator -> authenticator.type().equals(AuthenticatorType.TIMEBASED_OTP));
                        TextComponent comp = Component.text(" - Time Based One Time Password: ").color(TextColor.color(0x999999))
                                .append(Component.text(hasTimeBasedOTP ? "Enabled" : "Disabled")
                                        .color(hasTimeBasedOTP ? TextColor.color(0x64FF9D) : TextColor.color(0xFF7D6E))
                                );
                        if (!hasTimeBasedOTP) {
                            comp = comp.append(Component.text(" [Enable]").color(TextColor.color(0x64FF9D)).clickEvent(ClickEvent.runCommand("/auth register TIMEBASED_OTP")));
                        }

                        player.sendMessage(comp);

                        long yubikeys = authenticators.stream().filter(authenticator -> authenticator.type().equals(AuthenticatorType.YUBIKEY_OTP)).count();
                        player.sendMessage(Component.text(" - Yubikey OTP: ").color(TextColor.color(0x999999))
                                .append(Component.text(yubikeys).color(yubikeys > 0 ? TextColor.color(0x64FF9D) : TextColor.color(0xFF7D6E))
                                )
                                .append(Component.text(" registered ").color(TextColor.color(0x999999)))
                                .append(Component.text("[View Keys] ").color(TextColor.color(0xFFBE)).clickEvent(ClickEvent.runCommand("/auth manage yubikeys")))
                                .append(Component.text("[Add Key]\n").color(TextColor.color(0x64FF9D)).clickEvent(ClickEvent.runCommand("/auth register YUBIKEY_OTP")))
                                .append(Component.text("\n[Remove All Authentication]\n").color(TextColor.color(0xbd261e)).clickEvent(ClickEvent.runCommand("/auth remove all")))
                        );
                    }
                });
            }
            case "remove" -> {
                if (invocation.arguments().length >= 2 && invocation.arguments()[1].equalsIgnoreCase("all")) {

                    if (invocation.arguments().length == 2) {
                        player.sendMessage(Component.text("Are you sure you want to remove all authentication? To confirm please run ").color(TextColor.color(0x999999))
                                .append(Component.text(" /auth remove all [code]").color(TextColor.color(0xFFBE)).clickEvent(ClickEvent.suggestCommand("/auth remove all ")))
                        );
                        return;
                    }
                    verify(player, invocation.arguments()[2]).thenAccept((success) -> {
                        if (!success) {
                            player.sendMessage(Component.text("Invalid code!").color(TextColor.color(0xFF7D6E)));
                            return;
                        }
                        VelocityAuth.getInstance().getStorage().removeAuthenticators(player.getUniqueId()).thenAccept((removed) -> {
                            if (removed) {
                                player.sendMessage(Component.text("Removed all authentication!").color(TextColor.color(0x64FF9D)));
                            } else {
                                player.sendMessage(Component.text("Failed to remove all authentication!").color(TextColor.color(0xFF7D6E)));
                            }
                        });
                    });
                } else if (invocation.arguments().length >= 3 && invocation.arguments()[1].equalsIgnoreCase("yubikey")) {
                    if (invocation.arguments().length == 3) {
                        player.sendMessage(Component.text("Are you sure you want to this yubikey? To confirm please run ").color(TextColor.color(0x999999))
                                .append(Component.text(" /auth remove yubikey " + invocation.arguments()[2] + " [code]").color(TextColor.color(0xFFBE)).clickEvent(ClickEvent.suggestCommand("/auth remove yubikey " + invocation.arguments()[2] + " ")))
                        );
                        return;
                    }

                    verify(player, invocation.arguments()[3]).thenAccept((success) -> {
                        if (!success) {
                            player.sendMessage(Component.text("Invalid code!").color(TextColor.color(0xFF7D6E)));
                            return;
                        }

                        VelocityAuth.getInstance().getStorage().removeYubikey(player.getUniqueId(), invocation.arguments()[2]);
                        player.sendMessage(Component.text("Successfully removed this yubikey!").color(TextColor.color(0x64FF9D)));

                    });

                }
            }
            case "admin" -> {
                if (!player.hasPermission("velocityauth.admin")) {
                    player.sendMessage(Component.text("You do not have permission to use this command!").color(TextColor.color(0xFF7D6E)));
                    return;
                }
                if (invocation.arguments().length < 2) {
                    player.sendMessage(Component.text("\nCommand Usage ").color(TextColor.color(0xFF97))
                            .append(Component.text("/auth admin \n").color(TextColor.color(0xFFBE)))
                            .append(Component.text(" - ").color(TextColor.color(0x999999)).append(Component.text("/auth admin remove <uuid>").color(TextColor.color(0x78fdff)))
                                    .append(Component.text(": Removes all authenticators for a player.\n").color(TextColor.color(0x999999)))
                            )
                    );
                    return;
                }

                switch (invocation.arguments()[1].toLowerCase()){
                    case "remove" -> {
                        if (invocation.arguments().length < 3) {
                            player.sendMessage(Component.text("Usage: /auth admin remove <player>").color(TextColor.color(0xFF7D6E)));
                            return;
                        }
                        UUID uuid = UUID.fromString(invocation.arguments()[2]);
                        VelocityAuth.getInstance().getStorage().removeAuthenticators(uuid).thenAccept((removed) -> {
                            if (removed) {
                                player.sendMessage(Component.text("Removed all authentication for " + invocation.arguments()[2] + "!").color(TextColor.color(0x64FF9D)));
                            } else {
                                player.sendMessage(Component.text("Failed to remove all authentication for " + invocation.arguments()[2] + "!").color(TextColor.color(0xFF7D6E)));
                            }
                        });
                    }
                    default -> {
                        player.sendMessage(Component.text("\nCommand Usage ").color(TextColor.color(0xFF97))
                                .append(Component.text("/auth admin \n").color(TextColor.color(0xFFBE)))
                                .append(Component.text(" - ").color(TextColor.color(0x999999)).append(Component.text("/auth admin remove <uuid>").color(TextColor.color(0x78fdff)))
                                        .append(Component.text(": Removes all authenticators for a player.\n").color(TextColor.color(0x999999)))
                                )
                        );
                    }
                }
            }
            default -> {
                player.sendMessage(Component.text("\nCommand Usage ").color(TextColor.color(0xFF97))
                        .append(Component.text("/auth\n").color(TextColor.color(0xFFBE)))
                        .append(Component.text(" - ").color(TextColor.color(0x999999)).append(Component.text("/auth admin <subcommand>").color(TextColor.color(0x78fdff)))
                                .append(Component.text(": Administration commands for Velocity Auth\n").color(TextColor.color(0x999999)))
                        )
                        .append(Component.text(" - ").color(TextColor.color(0x999999)).append(Component.text("/auth manage").color(TextColor.color(0x78fdff)))
                                .append(Component.text(": Manage your own authenticators.\n").color(TextColor.color(0x999999)))
                        )
                );
            }
        }
    }

    public void register(Player player, String otp) {
        PendingRegistration registration = pendingRegistrations.get(player.getUniqueId());
        if (registration == null) return;

        if (registration.type.equals(AuthenticatorType.YUBIKEY_OTP)) {
            player.sendMessage(Component.text("Verifying Yubikey OTP...").color(TextColor.color(0x999999)).decorate(TextDecoration.ITALIC));
            YubikeyOTP.verify(otp, player.getUniqueId(), true).thenApply(result -> {
                if (result) {
                    pendingRegistrations.remove(player.getUniqueId());
                    player.sendMessage(Component.text("Registering...").color(TextColor.color(0x999999)).decorate(TextDecoration.ITALIC));
                    VelocityAuth.getInstance().getStorage().createAuthenticator(AuthenticatorType.YUBIKEY_OTP, YubikeyOTP.getKeyFromOTP(otp)).thenAccept((id) -> {
                        int authuser = VelocityAuth.getInstance().getStorage().getAuthUser(player.getUniqueId()).join();
                        if (authuser == -1) {
                            authuser = VelocityAuth.getInstance().getStorage().registerAuthUser(id).join();
                            if (authuser == -1) {
                                player.sendMessage(Component.text("Failed to register authenticator!").color(TextColor.color(0xFF7D6E)));
                                return;
                            }
                            boolean success = VelocityAuth.getInstance().getStorage().registerUser(player.getUniqueId(), authuser).join();
                            if (success) {
                                player.sendMessage(Component.text("Successfully registered authenticator!").color(TextColor.color(0x64FF9D)));
                            } else {
                                player.sendMessage(Component.text("Failed to register authenticator!").color(TextColor.color(0xFF7D6E)));
                            }
                        } else {
                            boolean success = VelocityAuth.getInstance().getStorage().addAuthenticator(authuser, id).join();
                            if (success) {
                                player.sendMessage(Component.text("Successfully registered authenticator!").color(TextColor.color(0x64FF9D)));
                            } else {
                                player.sendMessage(Component.text("Failed to register authenticator!").color(TextColor.color(0xFF7D6E)));
                            }
                        }
                    });
                } else {
                    player.sendMessage(Component.text("Failed to register Yubikey OTP!").color(TextColor.color(0xFF7D6E)));
                }
                return null;
            }).exceptionally(throwable -> {
                throwable.printStackTrace();
                return null;
            });

        } else if (registration.type.equals(AuthenticatorType.TIMEBASED_OTP)) {
            try {
                assert registration.secret != null;
                String code = TimeBasedOneTimePasswordUtil.generateCurrentNumberString(registration.secret);
                if (code.equals(otp)) {
                    pendingRegistrations.remove(player.getUniqueId());
                    player.sendMessage(Component.text("Registering...").color(TextColor.color(0x999999)).decorate(TextDecoration.ITALIC));
                    VelocityAuth.getInstance().getStorage().createAuthenticator(AuthenticatorType.TIMEBASED_OTP, registration.secret).thenAccept((id) -> {
                        int authuser = VelocityAuth.getInstance().getStorage().getAuthUser(player.getUniqueId()).join();
                        if (authuser == -1) {
                            authuser = VelocityAuth.getInstance().getStorage().registerAuthUser(id).join();
                            if (authuser == -1) {
                                player.sendMessage(Component.text("Failed to register authenticator!").color(TextColor.color(0xFF7D6E)));
                                return;
                            }
                            boolean success = VelocityAuth.getInstance().getStorage().registerUser(player.getUniqueId(), authuser).join();
                            if (success) {
                                player.sendMessage(Component.text("Successfully registered authenticator!").color(TextColor.color(0x64FF9D)));
                            } else {
                                player.sendMessage(Component.text("Failed to register authenticator!").color(TextColor.color(0xFF7D6E)));
                            }
                        } else {
                            boolean success = VelocityAuth.getInstance().getStorage().addAuthenticator(authuser, id).join();
                            if (success) {
                                player.sendMessage(Component.text("Successfully registered authenticator!").color(TextColor.color(0x64FF9D)));
                            } else {
                                player.sendMessage(Component.text("Failed to register authenticator!").color(TextColor.color(0xFF7D6E)));
                            }
                        }
                    });
                } else {
                    player.sendMessage(Component.text("Invalid code!").color(TextColor.color(0xFF7D6E)));
                }
            } catch (Exception e) {
                player.sendMessage(Component.text("Could not verify code!").color(TextColor.color(0xFF7D6E)));
            }
        }
    }

    private CompletableFuture<Boolean> verify(Player player, String otp) {
        if (otp.length() > 12) {
            return YubikeyOTP.verify(otp, player.getUniqueId());
        } else {
            return VelocityAuth.getInstance().getStorage().getTimeBasedSecret(player.getUniqueId()).thenApply((secret) -> {
                if (secret == null) return false;
                try {
                    String code = TimeBasedOneTimePasswordUtil.generateCurrentNumberString(secret);
                    return code.equals(otp);
                } catch (Exception e) {
                    return false;
                }
            });
        }
    }

    private record PendingRegistration(@NotNull AuthenticatorType type, @Nullable String secret) {
    }
}
