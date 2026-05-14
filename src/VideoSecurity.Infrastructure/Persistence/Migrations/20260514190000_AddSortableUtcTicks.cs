using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using VideoSecurity.Infrastructure.Persistence;

#nullable disable

namespace VideoSecurity.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    [DbContext(typeof(AppDbContext))]
    [Migration("20260514190000_AddSortableUtcTicks")]
    public partial class AddSortableUtcTicks : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<long>(
                name: "CreatedAtUtcTicks",
                table: "PlaybackSessions",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0L);

            migrationBuilder.AddColumn<long>(
                name: "ExpiresAtUtcTicks",
                table: "PlaybackSessions",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0L);

            migrationBuilder.AddColumn<long>(
                name: "CreatedAtUtcTicks",
                table: "AuditLogs",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0L);

            migrationBuilder.Sql("""
                UPDATE PlaybackSessions
                SET CreatedAtUtcTicks = COALESCE(CAST(ROUND((julianday(CreatedAt) - 2440587.5) * 864000000000) AS INTEGER) + 621355968000000000, 0),
                    ExpiresAtUtcTicks = COALESCE(CAST(ROUND((julianday(ExpiresAt) - 2440587.5) * 864000000000) AS INTEGER) + 621355968000000000, 0)
                WHERE CreatedAtUtcTicks = 0 OR ExpiresAtUtcTicks = 0;
                """);

            migrationBuilder.Sql("""
                UPDATE AuditLogs
                SET CreatedAtUtcTicks = COALESCE(CAST(ROUND((julianday(CreatedAt) - 2440587.5) * 864000000000) AS INTEGER) + 621355968000000000, 0)
                WHERE CreatedAtUtcTicks = 0;
                """);

            migrationBuilder.CreateIndex(
                name: "IX_PlaybackSessions_ExpiresAtUtcTicks",
                table: "PlaybackSessions",
                column: "ExpiresAtUtcTicks");

            migrationBuilder.CreateIndex(
                name: "IX_PlaybackSessions_Revoked_ExpiresAtUtcTicks",
                table: "PlaybackSessions",
                columns: new[] { "Revoked", "ExpiresAtUtcTicks" });

            migrationBuilder.CreateIndex(
                name: "IX_AuditLogs_CreatedAtUtcTicks",
                table: "AuditLogs",
                column: "CreatedAtUtcTicks");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_PlaybackSessions_ExpiresAtUtcTicks",
                table: "PlaybackSessions");

            migrationBuilder.DropIndex(
                name: "IX_PlaybackSessions_Revoked_ExpiresAtUtcTicks",
                table: "PlaybackSessions");

            migrationBuilder.DropIndex(
                name: "IX_AuditLogs_CreatedAtUtcTicks",
                table: "AuditLogs");

            migrationBuilder.DropColumn(
                name: "CreatedAtUtcTicks",
                table: "PlaybackSessions");

            migrationBuilder.DropColumn(
                name: "ExpiresAtUtcTicks",
                table: "PlaybackSessions");

            migrationBuilder.DropColumn(
                name: "CreatedAtUtcTicks",
                table: "AuditLogs");
        }
    }
}