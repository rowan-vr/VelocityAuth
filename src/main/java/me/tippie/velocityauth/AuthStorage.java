package me.tippie.velocityauth;

import com.mysql.jdbc.jdbc2.optional.MysqlConnectionPoolDataSource;
import com.mysql.jdbc.jdbc2.optional.MysqlDataSource;

import javax.sql.DataSource;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

public class AuthStorage {
    private final MysqlDataSource dataSource = new MysqlConnectionPoolDataSource();
    private final String prefix;

    public AuthStorage(String host, int port, String database, String user, String password, String prefix) {
        dataSource.setServerName(host);
        dataSource.setPortNumber(port);
        dataSource.setDatabaseName(database);
        dataSource.setUser(user);
        dataSource.setPassword(password);
        dataSource.setUseSSL(false);
        try {
            dataSource.setAllowPublicKeyRetrieval(true);
        } catch (SQLException e) {
            VelocityAuth.getInstance().getLogger().error("Failed to create a database connection.", e);
        }
        this.prefix = (prefix == null || prefix.equals("")) ? "" : (prefix + "_");
        try {
            testDataSource(dataSource);
        } catch (SQLException ex) {
            VelocityAuth.getInstance().getLogger().error("Could not establish database connection.", ex);
        }
        try {
            initDb();
        } catch (Exception ex) {
            VelocityAuth.getInstance().getLogger().error("Could not initialise database.", ex);
        }
    }


    public CompletableFuture<Integer> createAuthenticator(AuthenticatorType type, String secret) {
        return CompletableFuture.supplyAsync(() -> {
            try (Connection connection = dataSource.getConnection();
                 PreparedStatement statement = connection.prepareStatement("INSERT INTO " + prefix + "authenticators (type, secret) VALUES (?, ?)", Statement.RETURN_GENERATED_KEYS)) {
                statement.setString(1, type.toString());
                statement.setString(2, secret);
                if (statement.executeUpdate() == 1){
                    ResultSet rs = statement.getGeneratedKeys();
                    if (rs.next()) {
                        return rs.getInt(1);
                    }
                }
            } catch (SQLException ex) {
                VelocityAuth.getInstance().getLogger().error("Could not create authenticator.", ex);
            }
            return -1;
        });
    }

    public CompletableFuture<Integer> getAuthUser(UUID uuid) {
        return CompletableFuture.supplyAsync(() -> {
            try (Connection connection = dataSource.getConnection();
                 PreparedStatement statement = connection.prepareStatement("SELECT auth_user FROM " + prefix + "users WHERE uuid = ?")) {
                statement.setString(1, uuid.toString());
                ResultSet rs = statement.executeQuery();
                if (rs.next())
                    return rs.getInt(1);

            } catch (SQLException ex) {
                VelocityAuth.getInstance().getLogger().error("Could not get user.", ex);
            }
            return -1;
        });
    }

    public CompletableFuture<Boolean> addAuthenticator(int authUser, int authenticatorId) {
        return CompletableFuture.supplyAsync(() -> {
            try (Connection connection = dataSource.getConnection();
                 PreparedStatement statement = connection.prepareStatement("INSERT INTO " + prefix + "auth_users (id, authenticator) VALUES (?, ?)")) {
                statement.setInt(1, authUser);
                statement.setInt(2, authenticatorId);
                return statement.executeUpdate() == 1;

            } catch (SQLException ex) {
                VelocityAuth.getInstance().getLogger().error("Could not register auth user.", ex);
            }
            return false;
        });
    }

    public CompletableFuture<Integer> registerAuthUser(int authenticatorId) {
        return CompletableFuture.supplyAsync(() -> {
            try (Connection connection = dataSource.getConnection();
                 PreparedStatement statement = connection.prepareStatement("INSERT INTO " + prefix + "auth_users (authenticator) VALUES (?)", Statement.RETURN_GENERATED_KEYS)) {
                statement.setInt(1, authenticatorId);
                if (statement.executeUpdate() == 1){
                    ResultSet rs = statement.getGeneratedKeys();
                    if (rs.next()) {
                        return rs.getInt(1);
                    }
                };
            } catch (SQLException ex) {
                VelocityAuth.getInstance().getLogger().error("Could not register auth user.", ex);
            }
            return -1;
        });
    }

    public CompletableFuture<Boolean> registerUser(UUID uuid, int authUser) {
        return CompletableFuture.supplyAsync(() -> {
            try (Connection connection = dataSource.getConnection();
                 PreparedStatement statement = connection.prepareStatement("INSERT INTO " + prefix + "users (UUID, auth_user) VALUES (?, ?)")) {
                statement.setString(1, uuid.toString());
                statement.setInt(2, authUser);
                return statement.executeUpdate() == 1;

            } catch (SQLException ex) {
                VelocityAuth.getInstance().getLogger().error("Could not register user.", ex);
            }
            return false;
        });
    }

    public CompletableFuture<List<String>> getYubikeys(UUID uuid) {
        return CompletableFuture.supplyAsync(() -> {
            try (Connection connection = dataSource.getConnection();
                 PreparedStatement statement = connection.prepareStatement("SELECT authenticator.secret FROM " + prefix + "users AS user, " + prefix + "authenticators AS authenticator, "+prefix+"auth_users as auth_user " +
                         "WHERE user.uuid = ? AND user.auth_user = auth_user.id AND auth_user.authenticator = authenticator.id AND authenticator.type = 'YUBIKEY_OTP'")) {
                statement.setString(1, uuid.toString());
                ResultSet rs = statement.executeQuery();

                List<String> keys = new ArrayList<>();
                while (rs.next()){
                    keys.add(rs.getString(1));
                }
                return keys;
            } catch (SQLException ex) {
                VelocityAuth.getInstance().getLogger().error("Could not check authenticator.", ex);
            }
            return null;
        });
    }

    public CompletableFuture<String> getTimeBasedSecret(UUID uuid) {
        return CompletableFuture.supplyAsync(() -> {
            try (Connection connection = dataSource.getConnection();
                 PreparedStatement statement = connection.prepareStatement("SELECT authenticator.secret FROM " + prefix + "users AS user, " + prefix + "authenticators AS authenticator, "+prefix+"auth_users as auth_user " +
                         "WHERE user.uuid = ? AND user.auth_user = auth_user.id AND auth_user.authenticator = authenticator.id AND authenticator.type = 'TIMEBASED_OTP'")) {
                statement.setString(1, uuid.toString());
                ResultSet rs = statement.executeQuery();
                if (rs.next()){
                    return rs.getString(1);
                }
            } catch (SQLException ex) {
                VelocityAuth.getInstance().getLogger().error("Could not check authenticator.", ex);
            }
            return null;
        });
    }

    public CompletableFuture<List<Authenticator>> getAuthenticators(UUID uuid){
        return CompletableFuture.supplyAsync(() -> {
            try (Connection connection = dataSource.getConnection();
                 PreparedStatement statement = connection.prepareStatement("SELECT * FROM " + prefix + "users AS user, " + prefix + "authenticators AS authenticator, "+prefix+"auth_users as auth_user " +
                         "WHERE user.uuid = ? AND user.auth_user = auth_user.id AND auth_user.authenticator = authenticator.id")) {
                statement.setString(1, uuid.toString());
                ResultSet rs = statement.executeQuery();

                List<Authenticator> keys = new ArrayList<>();
                while (rs.next()){
                    keys.add(new Authenticator(
                            rs.getInt("authenticator.id"),
                            AuthenticatorType.valueOf(rs.getString("authenticator.type")),
                            rs.getString("authenticator.secret")
                    ));
                }
                return keys;
            } catch (SQLException ex) {
                VelocityAuth.getInstance().getLogger().error("Could not check authenticator.", ex);
            }
            return null;
        });
    }

    public CompletableFuture<Boolean> hasTimeBasedOTP(UUID uuid) {
        return CompletableFuture.supplyAsync(() -> {
            try (Connection connection = dataSource.getConnection();
                 PreparedStatement statement = connection.prepareStatement("SELECT * FROM " + prefix + "users AS user, " + prefix + "authenticators AS authenticator, "+prefix+"auth_users as auth_user " +
                         "WHERE user.uuid = ? AND user.auth_user = auth_user.id AND auth_user.authenticator = authenticator.id AND authenticator.type = 'TIMEBASED_OTP'")) {
                statement.setString(1, uuid.toString());
                ResultSet rs = statement.executeQuery();

                return rs.next();
            } catch (SQLException ex) {
                VelocityAuth.getInstance().getLogger().error("Could not check authenticator.", ex);
            }
            return null;
        });
    }

    public CompletableFuture<Boolean> setLastAddress(UUID uuid, InetAddress address) {
        return CompletableFuture.supplyAsync(() -> {
            try (Connection connection = dataSource.getConnection();
                 PreparedStatement statement = connection.prepareStatement("UPDATE " + prefix + "auth_users as auth, "+prefix+"users as user SET auth.last_ip = ? WHERE auth.id = user.auth_user AND user.uuid = ?")) {
                statement.setString(1, address.getHostAddress());
                statement.setString(2, uuid.toString());
                return statement.executeUpdate() == 1;
            } catch (SQLException ex) {
                VelocityAuth.getInstance().getLogger().error("Could not update last address.", ex);
            }
            return null;
        });
    }

    public CompletableFuture<Boolean> isLastAddress(UUID uuid, InetAddress address) {
        return CompletableFuture.supplyAsync(() -> {
            try (Connection connection = dataSource.getConnection();
                 PreparedStatement statement = connection.prepareStatement("SELECT * FROM " + prefix + "auth_users as auth, "+prefix+"users as user WHERE auth.last_ip = ? AND auth.id = user.auth_user AND user.uuid = ?")) {
                statement.setString(1, address.getHostAddress());
                statement.setString(2, uuid.toString());
                ResultSet rs = statement.executeQuery();
                return rs.next();
            } catch (SQLException ex) {
                VelocityAuth.getInstance().getLogger().error("Could not update last address.", ex);
            }
            return null;
        });
    }

    public CompletableFuture<Boolean> removeAuthenticators(UUID uuid) {
        return CompletableFuture.supplyAsync(() -> {
            try (Connection connection = dataSource.getConnection();
                 PreparedStatement statement = connection.prepareStatement("DELETE auth FROM " + prefix + "authenticators as auth, " + prefix + "auth_users as auth_user, "+prefix+"users as user WHERE auth_user.id = user.auth_user AND user.uuid = ? AND auth.id = auth_user.authenticator")) {
                statement.setString(1, uuid.toString());
                statement.executeUpdate();
                return true;
            } catch (SQLException ex) {
                VelocityAuth.getInstance().getLogger().error("Could not update remove all authenticators.", ex);
            }
            return false;
        });
    }

    public CompletableFuture<Boolean> removeYubikey(UUID uuid, String key) {
        return CompletableFuture.supplyAsync(() -> {
            try (Connection connection = dataSource.getConnection();
                 PreparedStatement statement = connection.prepareStatement("DELETE authenticator FROM " + prefix + "auth_users as auth, "+prefix+"users as user, "+prefix+"authenticators as authenticator" +
                         " WHERE auth.id = user.auth_user AND user.uuid = ? AND authenticator.id = auth.authenticator AND authenticator.type = 'YUBIKEY_OTP' AND authenticator.secret = ?")) {
                statement.setString(1, uuid.toString());
                statement.setString(2, key);
                statement.executeUpdate();
                return true;
            } catch (SQLException ex) {
                VelocityAuth.getInstance().getLogger().error("Could not update last address.", ex);
            }
            return false;
        });
    }

    public CompletableFuture<Boolean> isRegistered(UUID uuid){
        return this.getAuthUser(uuid).thenApply((authUser) -> authUser != -1);
    }

    public record Authenticator(int id, AuthenticatorType type, String secret) {}
    private void testDataSource(DataSource dataSource) throws SQLException {
        try (Connection conn = dataSource.getConnection()) {
            if (!conn.isValid(1000)) {
                throw new SQLException("Could not establish database connection.");
            }
        }
    }

    private void initDb() throws SQLException, IOException {
        String setup;
        try (InputStream in = this.getClass().getClassLoader().getResourceAsStream("dbsetup.sql")) {
            setup = new BufferedReader(new InputStreamReader(in)).lines().collect(Collectors.joining("\n"));
            setup = setup.replace("{prefix}", prefix);
        } catch (Exception e) {
            VelocityAuth.getInstance().getLogger().error("Could not read db setup file.", e);
            throw e;
        }
        String[] queries = setup.split(";");
        for (String query : queries) {
            if (query.trim().isEmpty()) continue;
            try (Connection conn = dataSource.getConnection();
                 PreparedStatement stmt = conn.prepareStatement(query)) {
                stmt.execute();
            }
        }
        VelocityAuth.getInstance().getLogger().info("Database successfully initialised.");
    }

    private Connection conn() throws SQLException {
        return dataSource.getConnection();
    }

}
