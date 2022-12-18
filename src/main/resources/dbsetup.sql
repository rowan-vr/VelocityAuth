CREATE TABLE IF NOT EXISTS `{prefix}authenticators`
(
    `id`     int                                  NOT NULL AUTO_INCREMENT,
    `secret` varchar(255)                         NOT NULL,
    `type`   ENUM ('YUBIKEY_OTP','TIMEBASED_OTP') NOT NULL,
    PRIMARY KEY (`id`)
);

CREATE TABLE IF NOT EXISTS `{prefix}auth_users`
(
    `id`          int NOT NULL AUTO_INCREMENT,
    `authenticator` int          NOT NULL,
    `last_ip`       varchar(255),
    PRIMARY KEY (`id`, `authenticator`),
    FOREIGN KEY (`authenticator`) REFERENCES `{prefix}authenticators` (`id`) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS `{prefix}users`
(
    `UUID`          varchar(255) NOT NULL,
    `auth_user`     int          NOT NULL,
    PRIMARY KEY (`UUID`)
);