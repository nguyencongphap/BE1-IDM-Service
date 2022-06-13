package com.github.klefstad_teaching.cs122b.idm.repo;

import com.github.klefstad_teaching.cs122b.core.error.ResultError;
import com.github.klefstad_teaching.cs122b.core.result.IDMResults;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.RefreshToken;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.User;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.type.TokenStatus;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.type.UserStatus;
import jdk.nashorn.internal.parser.Token;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Component;

import java.sql.Timestamp;
import java.sql.Types;
import java.time.Instant;

@Component
public class IDMRepo
{
    private final NamedParameterJdbcTemplate template;

    @Autowired
    public IDMRepo(NamedParameterJdbcTemplate template)
    {
        this.template = template;
    }

    public User getUserByEmail(String email) {
        String sql =
                "SELECT * " +
                        "FROM idm.user " +
                        "WHERE email = :emailValPlaceholder;"; //notice we mark varaibles with the ':var' format

        MapSqlParameterSource source =
                new MapSqlParameterSource() //For whatever ':var' we list a value and `Type` for value
                        .addValue("emailValPlaceholder", email, Types.VARCHAR); // Notice the lack of ':'  in the string here

        User userRetrieved =
                this.template.queryForObject(
                        sql,
                        source,
                        (rs, rowNum) ->
                                new User()
                                        .setId(rs.getInt("id"))
                                        .setEmail(rs.getString("email"))
                                        .setUserStatus(UserStatus.fromId(rs.getInt("user_status_id")))
                                        .setSalt(rs.getString("salt"))
                                        .setHashedPassword(rs.getString("hashed_password"))
                );

        return userRetrieved;
    }

    public User getUserByID(Integer id) {
        String sql =
                "SELECT * " +
                "FROM idm.user " +
                "WHERE id = :id;";

        MapSqlParameterSource source =
                new MapSqlParameterSource()
                        .addValue("id", id, Types.INTEGER);

        User userRetrieved =
                this.template.queryForObject(
                        sql,
                        source,
                        (rs, rowNum) ->
                                new User()
                                        .setId(rs.getInt("id"))
                                        .setEmail(rs.getString("email"))
                                        .setUserStatus(UserStatus.fromId(rs.getInt("user_status_id")))
                                        .setSalt(rs.getString("salt"))
                                        .setHashedPassword(rs.getString("hashed_password"))
                );

        return userRetrieved;
    }

    public void validateUserEmailAlreadyExist(String email) {
        try {
            String sql =
                    "SELECT * " +
                    "FROM idm.user " +
                    "WHERE email = :emailValPlaceholder;"; //notice we mark varaibles with the ':var' format

            MapSqlParameterSource source =
                    new MapSqlParameterSource() //For whatever ':var' we list a value and `Type` for value
                            .addValue("emailValPlaceholder", email, Types.VARCHAR); // Notice the lack of ':'  in the string here

            this.template.queryForObject(
                    sql,
                    source,
                    (rs, rowNum) ->
                            new User()
                                    .setId(rs.getInt("id"))
                                    .setEmail(rs.getString("email"))
                                    .setUserStatus(UserStatus.fromId(rs.getInt("user_status_id")))
                                    .setSalt(rs.getString("salt"))
                                    .setHashedPassword(rs.getString("hashed_password"))
            );

            throw new ResultError(IDMResults.USER_ALREADY_EXISTS);
        }
        catch (EmptyResultDataAccessException e) {
            ; // ALL GOOD! DO NOTHING
        }
    }

    public void insertUser(String email, Integer userStatusID, String salt, String hashedPassword) {
        String sql =
            "INSERT INTO idm.user (email, user_status_id, salt, hashed_password) " +
            "VALUES (:email, :userStatusID, :salt, :hashedPassword);";

        MapSqlParameterSource source =
            new MapSqlParameterSource()
                .addValue("email", email, Types.VARCHAR)
                .addValue("userStatusID", userStatusID, Types.INTEGER)
                .addValue("salt", salt, Types.CHAR)
                .addValue("hashedPassword", hashedPassword, Types.CHAR);

        this.template.update(sql, source);
    }

    public void insertRefreshToken(RefreshToken refreshToken) {
        String sql =
            "INSERT INTO idm.refresh_token (token, user_id, token_status_id, expire_time, max_life_time) " +
            "VALUES (:token, :user_id, :token_status_id, :expire_time, :max_life_time);";

        MapSqlParameterSource source =
                new MapSqlParameterSource()
                        .addValue("token", refreshToken.getToken(), Types.CHAR)
                        .addValue("user_id", refreshToken.getUserId(), Types.INTEGER)
                        .addValue("token_status_id", refreshToken.getTokenStatus().id(), Types.INTEGER)
                        .addValue("expire_time", Timestamp.from(refreshToken.getExpireTime()), Types.TIMESTAMP)
                        .addValue("max_life_time", Timestamp.from(refreshToken.getMaxLifeTime()), Types.TIMESTAMP);

        this.template.update(sql, source);
    }

    public void updateRefreshTokenExpireTime(Integer refreshTokenID, Instant newExpireTime) {
        String sql =
                "UPDATE idm.refresh_token " +
                "SET expire_time = :newExpireTime " +
                "WHERE id = :refreshTokenID;";

        MapSqlParameterSource source =
                new MapSqlParameterSource()
                        .addValue("newExpireTime", Timestamp.from(newExpireTime), Types.TIMESTAMP)
                        .addValue("refreshTokenID", refreshTokenID, Types.INTEGER);

        this.template.update(sql, source);
    }

    public void updateRefreshTokenStatusID(Integer refreshTokenID, Integer newStatusID) {
        String sql =
                "UPDATE idm.refresh_token " +
                "SET token_status_id = :newStatusID " +
                "WHERE id = :refreshTokenID;";

        MapSqlParameterSource source =
                new MapSqlParameterSource()
                        .addValue("newStatusID", newStatusID, Types.INTEGER)
                        .addValue("refreshTokenID", refreshTokenID, Types.INTEGER);

        this.template.update(sql, source);
    }

    public RefreshToken getRefreshTokenByToken(String token) {
        String sql =
                "SELECT * " +
                "FROM idm.refresh_token " +
                "WHERE token = :token;";

        MapSqlParameterSource source =
                new MapSqlParameterSource()
                        .addValue("token", token, Types.CHAR);

        RefreshToken refreshTokenRetrieved =
                this.template.queryForObject(
                        sql,
                        source,
                        (rs, rowNum) ->
                                new RefreshToken()
                                        .setId(rs.getInt("id"))
                                        .setToken(rs.getString("token"))
                                        .setUserId(rs.getInt("user_id"))
                                        .setTokenStatus(TokenStatus.fromId(rs.getInt("token_status_id")))
                                        .setExpireTime(rs.getTimestamp("expire_time").toInstant())
                                        .setMaxLifeTime(rs.getTimestamp("max_life_time").toInstant()));

        return refreshTokenRetrieved;
    }

}
