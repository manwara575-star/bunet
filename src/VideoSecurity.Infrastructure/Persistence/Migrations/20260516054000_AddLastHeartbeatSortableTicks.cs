using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using VideoSecurity.Infrastructure.Persistence;

#nullable disable

namespace VideoSecurity.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    [DbContext(typeof(AppDbContext))]
    [Migration("20260516054000_AddLastHeartbeatSortableTicks")]
    public partial class AddLastHeartbeatSortableTicks : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<long>(
                name: "LastHeartbeatAtUtcTicks",
                table: "PlaybackSessions",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0L);

            migrationBuilder.Sql("""
                UPDATE PlaybackSessions
                SET LastHeartbeatAtUtcTicks = COALESCE(CAST(ROUND((julianday(LastHeartbeatAt) - 2440587.5) * 864000000000) AS INTEGER) + 621355968000000000, 0)
                WHERE LastHeartbeatAt IS NOT NULL AND LastHeartbeatAtUtcTicks = 0;
                """);

            migrationBuilder.CreateIndex(
                name: "IX_PlaybackSessions_LastHeartbeatAtUtcTicks",
                table: "PlaybackSessions",
                column: "LastHeartbeatAtUtcTicks");

            migrationBuilder.CreateIndex(
                name: "IX_PlaybackSessions_Revoked_LastHeartbeatAtUtcTicks",
                table: "PlaybackSessions",
                columns: new[] { "Revoked", "LastHeartbeatAtUtcTicks" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_PlaybackSessions_LastHeartbeatAtUtcTicks",
                table: "PlaybackSessions");

            migrationBuilder.DropIndex(
                name: "IX_PlaybackSessions_Revoked_LastHeartbeatAtUtcTicks",
                table: "PlaybackSessions");

            migrationBuilder.DropColumn(
                name: "LastHeartbeatAtUtcTicks",
                table: "PlaybackSessions");
        }
    }
}
