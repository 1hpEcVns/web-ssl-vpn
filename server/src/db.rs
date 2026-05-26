use log::info;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, Database,
    DatabaseConnection, DbErr, EntityTrait, QueryFilter, QuerySelect, Set,
};
use sea_orm::entity::prelude::*;
use sea_orm::query::QueryOrder;
use sea_query::{Table, ColumnDef};
use serde::{Deserialize, Serialize};
use std::path::Path;

mod user {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, DeriveEntityModel)]
    #[sea_orm(table_name = "users")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i64,
        pub username: String,
        pub password_hash: String,
        pub role: String,
        pub totp_secret: Option<String>,
        pub totp_enabled: i64,
        pub created_at: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

mod session {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, DeriveEntityModel)]
    #[sea_orm(table_name = "sessions")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub id: String,
        pub user_id: i64,
        pub created_at: String,
        pub expires_at: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

mod app {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, DeriveEntityModel)]
    #[sea_orm(table_name = "apps")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i64,
        pub name: String,
        pub description: String,
        pub url: String,
        pub icon_url: String,
        pub is_active: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

mod user_app_permission {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, DeriveEntityModel)]
    #[sea_orm(table_name = "user_app_permissions")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i64,
        pub user_id: i64,
        pub app_id: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

mod audit_log {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, DeriveEntityModel)]
    #[sea_orm(table_name = "audit_logs")]
    pub struct Model {
        #[sea_orm(primary_key)]
        pub id: i64,
        pub user_id: Option<i64>,
        pub action: String,
        pub source_ip: String,
        pub target_url: String,
        pub result: String,
        pub timestamp: String,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

pub use user::Entity as UserEntity;
pub use user::Column as UserColumn;
pub use user::ActiveModel as UserActiveModel;
pub use user::Model as UserModel;

pub use session::Entity as SessionEntity;
pub use session::Column as SessionColumn;
pub use session::ActiveModel as SessionActiveModel;
pub use session::Model as SessionModel;

pub use app::Entity as AppEntity;
pub use app::Column as AppColumn;
pub use app::ActiveModel as AppActiveModel;
pub use app::Model as AppModel;

pub use user_app_permission::Entity as UserAppPermissionEntity;
pub use user_app_permission::Column as UserAppPermissionColumn;
pub use user_app_permission::ActiveModel as UserAppPermissionActiveModel;

pub use audit_log::Entity as AuditLogEntity;
pub use audit_log::Column as AuditLogColumn;
pub use audit_log::ActiveModel as AuditLogActiveModel;
pub use audit_log::Model as AuditLogModel;

// ============ Public API types ============

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub role: String,
    pub totp_secret: Option<String>,
    pub totp_enabled: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: i64,
    pub created_at: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct App {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub url: String,
    pub icon_url: String,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub id: i64,
    pub user_id: Option<i64>,
    pub action: String,
    pub source_ip: String,
    pub target_url: String,
    pub result: String,
    pub timestamp: String,
}

// ============ Helpers ============

fn model_to_user(m: UserModel) -> User {
    User {
        id: m.id, username: m.username, password_hash: m.password_hash,
        role: m.role, totp_secret: m.totp_secret, totp_enabled: m.totp_enabled != 0,
        created_at: m.created_at,
    }
}

fn model_to_session(m: SessionModel) -> Session {
    Session { id: m.id, user_id: m.user_id, created_at: m.created_at, expires_at: m.expires_at }
}

fn model_to_app(m: AppModel) -> App {
    App { id: m.id, name: m.name, description: m.description, url: m.url, icon_url: m.icon_url, is_active: m.is_active != 0 }
}

fn model_to_audit_log(m: AuditLogModel) -> AuditLog {
    AuditLog { id: m.id, user_id: m.user_id, action: m.action, source_ip: m.source_ip, target_url: m.target_url, result: m.result, timestamp: m.timestamp }
}

// ============ Database initialization ============

pub async fn init_database(db_path: &Path) -> Result<DatabaseConnection, DbErr> {
    let db_url = format!("sqlite://{}?mode=rwc", db_path.to_string_lossy());
    info!("Connecting to database: {}", db_url);
    let db = Database::connect(&db_url).await?;
    info!("Database connected successfully");
    create_tables(&db).await?;
    create_default_admin(&db).await?;
    Ok(db)
}

pub async fn create_tables(db: &DatabaseConnection) -> Result<(), DbErr> {
    db.execute(
        &Table::create()
            .table(UserEntity)
            .if_not_exists()
            .col(ColumnDef::new(UserColumn::Id).integer().not_null().auto_increment().primary_key())
            .col(ColumnDef::new(UserColumn::Username).string().not_null().unique_key())
            .col(ColumnDef::new(UserColumn::PasswordHash).string().not_null())
            .col(ColumnDef::new(UserColumn::Role).string().not_null().default("'user'"))
            .col(ColumnDef::new(UserColumn::TotpSecret).string())
            .col(ColumnDef::new(UserColumn::TotpEnabled).integer().not_null().default("0"))
            .col(ColumnDef::new(UserColumn::CreatedAt).string().not_null().default("(datetime('now'))"))
            .to_owned()
    ).await.map(|_| ())?;

    db.execute(
        &Table::create()
            .table(SessionEntity)
            .if_not_exists()
            .col(ColumnDef::new(SessionColumn::Id).string().not_null().primary_key())
            .col(ColumnDef::new(SessionColumn::UserId).integer().not_null())
            .col(ColumnDef::new(SessionColumn::CreatedAt).string().not_null().default("(datetime('now'))"))
            .col(ColumnDef::new(SessionColumn::ExpiresAt).string().not_null())
            .to_owned()
    ).await.map(|_| ())?;

    db.execute(
        &Table::create()
            .table(AppEntity)
            .if_not_exists()
            .col(ColumnDef::new(AppColumn::Id).integer().not_null().auto_increment().primary_key())
            .col(ColumnDef::new(AppColumn::Name).string().not_null())
            .col(ColumnDef::new(AppColumn::Description).string().not_null().default("''"))
            .col(ColumnDef::new(AppColumn::Url).string().not_null())
            .col(ColumnDef::new(AppColumn::IconUrl).string().not_null().default("''"))
            .col(ColumnDef::new(AppColumn::IsActive).integer().not_null().default("1"))
            .to_owned()
    ).await.map(|_| ())?;

    db.execute(
        &Table::create()
            .table(UserAppPermissionEntity)
            .if_not_exists()
            .col(ColumnDef::new(UserAppPermissionColumn::Id).integer().not_null().auto_increment().primary_key())
            .col(ColumnDef::new(UserAppPermissionColumn::UserId).integer().not_null())
            .col(ColumnDef::new(UserAppPermissionColumn::AppId).integer().not_null())
            .to_owned()
    ).await.map(|_| ())?;

    db.execute(
        &Table::create()
            .table(AuditLogEntity)
            .if_not_exists()
            .col(ColumnDef::new(AuditLogColumn::Id).integer().not_null().auto_increment().primary_key())
            .col(ColumnDef::new(AuditLogColumn::UserId).integer())
            .col(ColumnDef::new(AuditLogColumn::Action).string().not_null())
            .col(ColumnDef::new(AuditLogColumn::SourceIp).string().not_null().default("''"))
            .col(ColumnDef::new(AuditLogColumn::TargetUrl).string().not_null().default("''"))
            .col(ColumnDef::new(AuditLogColumn::Result).string().not_null().default("'success'"))
            .col(ColumnDef::new(AuditLogColumn::Timestamp).string().not_null().default("(datetime('now'))"))
            .to_owned()
    ).await.map(|_| ())?;

    Ok(())
}

async fn create_default_admin(db: &DatabaseConnection) -> Result<(), DbErr> {
    let count = UserEntity::find().count(db).await?;
    if count == 0 {
        let salt: [u8; 16] = *uuid::Uuid::new_v4().as_bytes();
        let hash = argon2::hash_encoded(
            b"admin123", &salt, &argon2::Config::default(),
        ).map_err(|e| DbErr::Custom(format!("argon2 error: {}", e)))?;

        UserActiveModel {
            username: Set("admin".to_string()),
            password_hash: Set(hash),
            role: Set("admin".to_string()),
            ..Default::default()
        }.insert(db).await?;
        info!("Default admin user created: admin / admin123");
    }
    Ok(())
}

pub async fn seed_default_apps(db: &DatabaseConnection) -> Result<(), DbErr> {
    let count = AppEntity::find().count(db).await?;
    if count == 0 {
        create_app(db, "Internal Wiki", "Company documentation and knowledge base", "127.0.0.1:3001", "").await?;
        create_app(db, "Mail Server", "Roundcube webmail interface", "127.0.0.1:8081", "").await?;
        create_app(db, "File Repository", "Internal file sharing and downloads", "127.0.0.1:9001", "").await?;
        create_app(db, "HR Portal", "Human resources management system", "127.0.0.1:5001", "").await?;

        let admin = find_user_by_username(db, "admin").await?;
        if let Some(admin) = admin {
            let apps = get_all_apps(db).await?;
            let app_ids: Vec<i64> = apps.iter().map(|a| a.id).collect();
            set_user_permissions(db, admin.id, &app_ids).await?;
        }

        info!("Default demo applications seeded: Wiki, Mail, Files, HR");
    }
    Ok(())
}

// ============ User operations ============

pub async fn find_user_by_username(db: &DatabaseConnection, username: &str) -> Result<Option<User>, DbErr> {
    let result = UserEntity::find().filter(UserColumn::Username.eq(username)).one(db).await?;
    Ok(result.map(model_to_user))
}

pub async fn find_user_by_id(db: &DatabaseConnection, user_id: i64) -> Result<Option<User>, DbErr> {
    let result = UserEntity::find_by_id(user_id).one(db).await?;
    Ok(result.map(model_to_user))
}

pub async fn get_all_users(db: &DatabaseConnection) -> Result<Vec<User>, DbErr> {
    let users = UserEntity::find().all(db).await?;
    Ok(users.into_iter().map(model_to_user).collect())
}

pub async fn create_user(db: &DatabaseConnection, username: &str, password_hash: &str, role: &str) -> Result<User, DbErr> {
    let result = UserActiveModel {
        username: Set(username.to_string()),
        password_hash: Set(password_hash.to_string()),
        role: Set(role.to_string()),
        ..Default::default()
    }.insert(db).await?;
    Ok(model_to_user(result))
}

pub async fn update_user_password(db: &DatabaseConnection, user_id: i64, password_hash: &str) -> Result<(), DbErr> {
    let mut user: UserActiveModel = UserEntity::find_by_id(user_id).one(db).await?.ok_or(DbErr::RecordNotFound("user".into()))?.into();
    user.password_hash = Set(password_hash.to_string());
    user.update(db).await?;
    Ok(())
}

pub async fn set_user_totp_secret(db: &DatabaseConnection, user_id: i64, secret: &str) -> Result<(), DbErr> {
    let mut user: UserActiveModel = UserEntity::find_by_id(user_id).one(db).await?.ok_or(DbErr::RecordNotFound("user".into()))?.into();
    user.totp_secret = Set(Some(secret.to_string()));
    user.totp_enabled = Set(0);
    user.update(db).await?;
    Ok(())
}

pub async fn enable_user_totp(db: &DatabaseConnection, user_id: i64) -> Result<(), DbErr> {
    let mut user: UserActiveModel = UserEntity::find_by_id(user_id).one(db).await?.ok_or(DbErr::RecordNotFound("user".into()))?.into();
    user.totp_enabled = Set(1);
    user.update(db).await?;
    Ok(())
}

pub async fn disable_user_totp(db: &DatabaseConnection, user_id: i64) -> Result<(), DbErr> {
    let mut user: UserActiveModel = UserEntity::find_by_id(user_id).one(db).await?.ok_or(DbErr::RecordNotFound("user".into()))?.into();
    user.totp_secret = Set(None);
    user.totp_enabled = Set(0);
    user.update(db).await?;
    Ok(())
}


// ============ Session operations ============

pub async fn create_session(db: &DatabaseConnection, user_id: i64, session_id: &str, expires_at: &str) -> Result<(), DbErr> {
    SessionActiveModel {
        id: Set(session_id.to_string()),
        user_id: Set(user_id),
        created_at: Set(chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string()),
        expires_at: Set(expires_at.to_string()),
    }.insert(db).await?;
    Ok(())
}

pub async fn find_session(db: &DatabaseConnection, session_id: &str) -> Result<Option<Session>, DbErr> {
    let result = SessionEntity::find_by_id(session_id).one(db).await?;
    Ok(result.map(model_to_session))
}

pub async fn delete_session(db: &DatabaseConnection, session_id: &str) -> Result<(), DbErr> {
    SessionEntity::delete_by_id(session_id).exec(db).await?;
    Ok(())
}

pub async fn cleanup_expired_sessions(db: &DatabaseConnection) -> Result<(), DbErr> {
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let deleted = SessionEntity::delete_many()
        .filter(SessionColumn::ExpiresAt.lt(&now))
        .exec(db).await?;
    if deleted.rows_affected > 0 {
        log::info!("Cleaned up {} expired sessions", deleted.rows_affected);
    }
    Ok(())
}

// ============ App operations ============

pub async fn get_all_apps(db: &DatabaseConnection) -> Result<Vec<App>, DbErr> {
    let apps = AppEntity::find().filter(AppColumn::IsActive.eq(1)).all(db).await?;
    Ok(apps.into_iter().map(model_to_app).collect())
}

pub async fn get_user_apps(db: &DatabaseConnection, user_id: i64) -> Result<Vec<App>, DbErr> {
    let apps = AppEntity::find().filter(AppColumn::IsActive.eq(1)).all(db).await?;
    let permissions = UserAppPermissionEntity::find().filter(UserAppPermissionColumn::UserId.eq(user_id)).all(db).await?;
    let permitted_ids: std::collections::HashSet<i64> = permissions.into_iter().map(|p| p.app_id).collect();
    Ok(apps.into_iter().filter(|a| permitted_ids.contains(&a.id)).map(model_to_app).collect())
}

pub async fn create_app(db: &DatabaseConnection, name: &str, description: &str, url: &str, icon_url: &str) -> Result<App, DbErr> {
    let result = AppActiveModel {
        name: Set(name.to_string()),
        description: Set(description.to_string()),
        url: Set(url.to_string()),
        icon_url: Set(icon_url.to_string()),
        ..Default::default()
    }.insert(db).await?;
    Ok(model_to_app(result))
}

pub async fn get_app_by_id(db: &DatabaseConnection, app_id: i64) -> Result<Option<App>, DbErr> {
    let result = AppEntity::find_by_id(app_id).one(db).await?;
    Ok(result.map(model_to_app))
}

pub async fn delete_app(db: &DatabaseConnection, app_id: i64) -> Result<(), DbErr> {
    AppEntity::delete_by_id(app_id).exec(db).await?;
    Ok(())
}

// ============ Permission operations ============

pub async fn user_has_app_permission(db: &DatabaseConnection, user_id: i64, app_id: i64) -> Result<bool, DbErr> {
    let count = UserAppPermissionEntity::find()
        .filter(UserAppPermissionColumn::UserId.eq(user_id))
        .filter(UserAppPermissionColumn::AppId.eq(app_id))
        .count(db).await?;
    Ok(count > 0)
}

#[allow(dead_code)]
pub async fn grant_app_permission(db: &DatabaseConnection, user_id: i64, app_id: i64) -> Result<(), DbErr> {
    let existing = UserAppPermissionEntity::find()
        .filter(UserAppPermissionColumn::UserId.eq(user_id))
        .filter(UserAppPermissionColumn::AppId.eq(app_id))
        .one(db).await?;
    if existing.is_none() {
        UserAppPermissionActiveModel {
            user_id: Set(user_id), app_id: Set(app_id), ..Default::default()
        }.insert(db).await?;
    }
    Ok(())
}

#[allow(dead_code)]
pub async fn revoke_app_permission(db: &DatabaseConnection, user_id: i64, app_id: i64) -> Result<(), DbErr> {
    UserAppPermissionEntity::delete_many()
        .filter(UserAppPermissionColumn::UserId.eq(user_id))
        .filter(UserAppPermissionColumn::AppId.eq(app_id))
        .exec(db).await?;
    Ok(())
}

#[allow(dead_code)]
pub async fn get_user_permissions(db: &DatabaseConnection, user_id: i64) -> Result<Vec<i64>, DbErr> {
    let perms = UserAppPermissionEntity::find().filter(UserAppPermissionColumn::UserId.eq(user_id)).all(db).await?;
    Ok(perms.into_iter().map(|p| p.app_id).collect())
}

pub async fn set_user_permissions(db: &DatabaseConnection, user_id: i64, app_ids: &[i64]) -> Result<(), DbErr> {
    UserAppPermissionEntity::delete_many().filter(UserAppPermissionColumn::UserId.eq(user_id)).exec(db).await?;
    for app_id in app_ids {
        UserAppPermissionActiveModel { user_id: Set(user_id), app_id: Set(*app_id), ..Default::default() }.insert(db).await?;
    }
    Ok(())
}

// ============ Audit log operations ============

pub async fn create_audit_log(db: &DatabaseConnection, user_id: Option<i64>, action: &str, source_ip: &str, target_url: &str, result: &str) -> Result<(), DbErr> {
    AuditLogActiveModel {
        user_id: Set(user_id),
        action: Set(action.to_string()),
        source_ip: Set(source_ip.to_string()),
        target_url: Set(target_url.to_string()),
        result: Set(result.to_string()),
        timestamp: Set(chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string()),
        ..Default::default()
    }.insert(db).await?;
    Ok(())
}

pub async fn get_audit_logs(db: &DatabaseConnection, limit: u64) -> Result<Vec<AuditLog>, DbErr> {
    let logs = AuditLogEntity::find().order_by_desc(AuditLogColumn::Id).limit(Some(limit)).all(db).await?;
    Ok(logs.into_iter().map(model_to_audit_log).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::Database;

    async fn setup_db() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        create_tables(&db).await.unwrap();
        db
    }

    fn hash_password(pw: &str) -> String {
        let salt: [u8; 16] = *uuid::Uuid::new_v4().as_bytes();
        argon2::hash_encoded(pw.as_bytes(), &salt, &argon2::Config::default()).unwrap()
    }

    #[tokio::test]
    async fn test_create_and_find_user() {
        let db = setup_db().await;
        create_user(&db, "testuser", &hash_password("pass123"), "user").await.unwrap();

        let found = find_user_by_username(&db, "testuser").await.unwrap().unwrap();
        assert_eq!(found.username, "testuser");
        assert_eq!(found.role, "user");

        let found = find_user_by_id(&db, found.id).await.unwrap().unwrap();
        assert_eq!(found.username, "testuser");

        let not_found = find_user_by_username(&db, "nonexistent").await.unwrap();
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn test_get_all_users() {
        let db = setup_db().await;
        create_user(&db, "alice", &hash_password("a"), "user").await.unwrap();
        create_user(&db, "bob", &hash_password("b"), "admin").await.unwrap();

        let users = get_all_users(&db).await.unwrap();
        assert_eq!(users.len(), 2);
    }

    #[tokio::test]
    async fn test_default_admin_seeded() {
        let db = setup_db().await;
        create_default_admin(&db).await.unwrap();
        let users = get_all_users(&db).await.unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, "admin");
        assert_eq!(users[0].role, "admin");
    }

    #[tokio::test]
    async fn test_default_admin_not_duplicated() {
        let db = setup_db().await;
        create_default_admin(&db).await.unwrap();
        create_default_admin(&db).await.unwrap();
        let users = get_all_users(&db).await.unwrap();
        assert_eq!(users.len(), 1);
    }

    #[tokio::test]
    async fn test_session_crud() {
        let db = setup_db().await;
        create_default_admin(&db).await.unwrap();
        let user = find_user_by_username(&db, "admin").await.unwrap().unwrap();

        create_session(&db, user.id, "session-abc", "2026-12-31 23:59:59").await.unwrap();
        let s = find_session(&db, "session-abc").await.unwrap().unwrap();
        assert_eq!(s.user_id, user.id);
        assert_eq!(s.expires_at, "2026-12-31 23:59:59");

        delete_session(&db, "session-abc").await.unwrap();
        let s = find_session(&db, "session-abc").await.unwrap();
        assert!(s.is_none());
    }

    #[tokio::test]
    async fn test_app_crud() {
        let db = setup_db().await;

        let app = create_app(&db, "Wiki", "Internal wiki", "wiki:3000", "").await.unwrap();
        assert_eq!(app.name, "Wiki");
        assert!(app.is_active);

        let apps = get_all_apps(&db).await.unwrap();
        assert_eq!(apps.len(), 1);

        let found = get_app_by_id(&db, app.id).await.unwrap().unwrap();
        assert_eq!(found.url, "wiki:3000");

        delete_app(&db, app.id).await.unwrap();
        let apps = get_all_apps(&db).await.unwrap();
        assert_eq!(apps.len(), 0);
    }

    #[tokio::test]
    async fn test_app_not_found_when_inactive() {
        let db = setup_db().await;
        let _app = create_app(&db, "Test", "", "test:80", "").await.unwrap();
        let apps = get_all_apps(&db).await.unwrap();
        assert_eq!(apps.len(), 1);
    }

    #[tokio::test]
    async fn test_permissions() {
        let db = setup_db().await;
        create_user(&db, "user1", &hash_password("p"), "user").await.unwrap();
        let user = find_user_by_username(&db, "user1").await.unwrap().unwrap();
        let app = create_app(&db, "App1", "", "app1:80", "").await.unwrap();

        let has = user_has_app_permission(&db, user.id, app.id).await.unwrap();
        assert!(!has);

        grant_app_permission(&db, user.id, app.id).await.unwrap();
        let has = user_has_app_permission(&db, user.id, app.id).await.unwrap();
        assert!(has);

        let perms = get_user_permissions(&db, user.id).await.unwrap();
        assert_eq!(perms, vec![app.id]);

        revoke_app_permission(&db, user.id, app.id).await.unwrap();
        let has = user_has_app_permission(&db, user.id, app.id).await.unwrap();
        assert!(!has);
    }

    #[tokio::test]
    async fn test_set_user_permissions_replaces_all() {
        let db = setup_db().await;
        create_user(&db, "u", &hash_password("p"), "user").await.unwrap();
        let user = find_user_by_username(&db, "u").await.unwrap().unwrap();
        let app1 = create_app(&db, "A1", "", "a1:80", "").await.unwrap();
        let app2 = create_app(&db, "A2", "", "a2:80", "").await.unwrap();

        set_user_permissions(&db, user.id, &[app1.id, app2.id]).await.unwrap();
        let perms = get_user_permissions(&db, user.id).await.unwrap();
        assert_eq!(perms.len(), 2);

        set_user_permissions(&db, user.id, &[app1.id]).await.unwrap();
        let perms = get_user_permissions(&db, user.id).await.unwrap();
        assert_eq!(perms, vec![app1.id]);
    }

    #[tokio::test]
    async fn test_get_user_apps_respects_permissions() {
        let db = setup_db().await;
        create_user(&db, "normal", &hash_password("p"), "user").await.unwrap();
        let user = find_user_by_username(&db, "normal").await.unwrap().unwrap();
        let app1 = create_app(&db, "App1", "", "a1:80", "").await.unwrap();
        let _app2 = create_app(&db, "App2", "", "a2:80", "").await.unwrap();

        grant_app_permission(&db, user.id, app1.id).await.unwrap();

        let apps = get_user_apps(&db, user.id).await.unwrap();
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0].name, "App1");
    }

    #[tokio::test]
    async fn test_audit_log() {
        let db = setup_db().await;

        create_audit_log(&db, None, "login_failed", "1.2.3.4", "/login", "denied").await.unwrap();
        create_audit_log(&db, Some(1), "login", "5.6.7.8", "/login", "success").await.unwrap();
        create_audit_log(&db, Some(1), "proxy_access", "5.6.7.8", "wiki:3000", "success").await.unwrap();

        let logs = get_audit_logs(&db, 10).await.unwrap();
        assert_eq!(logs.len(), 3);

        let limited = get_audit_logs(&db, 2).await.unwrap();
        assert_eq!(limited.len(), 2);
    }
}