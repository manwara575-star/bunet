using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace VideoSecurity.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class EnterpriseHardening : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "PolicyId",
                table: "Videos",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "SensitivityTier",
                table: "Videos",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<string>(
                name: "DeviceFingerprintHash",
                table: "PlaybackSessions",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<double>(
                name: "LastKnownPositionSeconds",
                table: "PlaybackSessions",
                type: "REAL",
                nullable: false,
                defaultValue: 0.0);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "PlaybackStartedAt",
                table: "PlaybackSessions",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "RevokedAt",
                table: "PlaybackSessions",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "WatermarkPayloadHash",
                table: "PlaybackSessions",
                type: "TEXT",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "AuditLogs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    ActorUserId = table.Column<string>(type: "TEXT", maxLength: 450, nullable: false),
                    Action = table.Column<int>(type: "INTEGER", nullable: false),
                    EntityType = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    EntityId = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    MetadataJson = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: true),
                    IpHash = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    UserAgentHash = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AuditLogs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "SigningKeyVersions",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Purpose = table.Column<int>(type: "INTEGER", nullable: false),
                    Version = table.Column<int>(type: "INTEGER", nullable: false),
                    IsActive = table.Column<bool>(type: "INTEGER", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    RetiredAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: true),
                    Notes = table.Column<string>(type: "TEXT", maxLength: 512, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SigningKeyVersions", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "VideoSecurityPolicies",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    Tier = table.Column<int>(type: "INTEGER", nullable: false),
                    EmbedTtlSeconds = table.Column<int>(type: "INTEGER", nullable: false),
                    HeartbeatIntervalSeconds = table.Column<int>(type: "INTEGER", nullable: false),
                    MaxConcurrentSessions = table.Column<int>(type: "INTEGER", nullable: false),
                    RequireWatermark = table.Column<bool>(type: "INTEGER", nullable: false),
                    RevokeOnWatermarkTamper = table.Column<bool>(type: "INTEGER", nullable: false),
                    AllowIpDrift = table.Column<bool>(type: "INTEGER", nullable: false),
                    AutoRevokeRiskThreshold = table.Column<int>(type: "INTEGER", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_VideoSecurityPolicies", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "WebhookEvents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    EventId = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    VideoGuid = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Status = table.Column<int>(type: "INTEGER", nullable: true),
                    RawPayload = table.Column<string>(type: "TEXT", maxLength: 8000, nullable: true),
                    ReceivedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    ProcessedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: true),
                    Attempts = table.Column<int>(type: "INTEGER", nullable: false),
                    LastError = table.Column<string>(type: "TEXT", maxLength: 2000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_WebhookEvents", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AuditLogs_ActorUserId",
                table: "AuditLogs",
                column: "ActorUserId");

            migrationBuilder.CreateIndex(
                name: "IX_AuditLogs_CreatedAt",
                table: "AuditLogs",
                column: "CreatedAt");

            migrationBuilder.CreateIndex(
                name: "IX_SigningKeyVersions_Purpose_Version",
                table: "SigningKeyVersions",
                columns: new[] { "Purpose", "Version" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_VideoSecurityPolicies_Tier",
                table: "VideoSecurityPolicies",
                column: "Tier",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_WebhookEvents_EventId",
                table: "WebhookEvents",
                column: "EventId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_WebhookEvents_ReceivedAt",
                table: "WebhookEvents",
                column: "ReceivedAt");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AuditLogs");

            migrationBuilder.DropTable(
                name: "SigningKeyVersions");

            migrationBuilder.DropTable(
                name: "VideoSecurityPolicies");

            migrationBuilder.DropTable(
                name: "WebhookEvents");

            migrationBuilder.DropColumn(
                name: "PolicyId",
                table: "Videos");

            migrationBuilder.DropColumn(
                name: "SensitivityTier",
                table: "Videos");

            migrationBuilder.DropColumn(
                name: "DeviceFingerprintHash",
                table: "PlaybackSessions");

            migrationBuilder.DropColumn(
                name: "LastKnownPositionSeconds",
                table: "PlaybackSessions");

            migrationBuilder.DropColumn(
                name: "PlaybackStartedAt",
                table: "PlaybackSessions");

            migrationBuilder.DropColumn(
                name: "RevokedAt",
                table: "PlaybackSessions");

            migrationBuilder.DropColumn(
                name: "WatermarkPayloadHash",
                table: "PlaybackSessions");
        }
    }
}
