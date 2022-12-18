package me.tippie.velocityauth;

import com.google.inject.Inject;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.ProxyServer;
import lombok.Getter;
import ninja.leaping.configurate.ConfigurationNode;
import ninja.leaping.configurate.yaml.YAMLConfigurationLoader;
import org.slf4j.Logger;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

@Plugin(
        id = "VelocityAuth",
        name = "VelocityAuth",
        version = "1.0-SNAPSHOT",
        authors = {"Tippie_"}
)
public class VelocityAuth {

    @Getter @Inject private Logger logger;
    @Getter
    @Inject private ProxyServer server;
    @Getter @Inject @DataDirectory
    private Path dataDirectory;

    private ConfigurationNode configuration;

    @Subscribe
    public void onProxyInitialization(ProxyInitializeEvent event) {
        File configFile = new File(dataDirectory.toFile(), "config.yml");
        if (!configFile.exists()) {
            configFile.getParentFile().mkdirs();
            InputStream is = this.getClass().getClassLoader().getResourceAsStream("config.yml");
            try (InputStreamReader streamReader =
                         new InputStreamReader(is, StandardCharsets.UTF_8); BufferedReader reader = new BufferedReader(streamReader); FileWriter writer = new FileWriter(configFile)) {
                String line;
                while ((line = reader.readLine()) != null) {
                    writer.write(line);
                }
                writer.flush();
            } catch (IOException e) {
                logger.error("Could not create config file!", e);
            }
        }
        try {
            configuration = YAMLConfigurationLoader.builder().setPath(configFile.toPath()).build().load();
        } catch (Exception e) {
            logger.error("Failed to load configuration file!");
            e.printStackTrace();
        }

    }
}
