using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace VideoSecurity.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddOperationalIndexes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateIndex(
                name: "IX_VideoSecurityEvents_Type_CreatedAt",
                table: "VideoSecurityEvents",
                columns: new[] { "Type", "CreatedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_VideoSecurityEvents_VideoId_CreatedAt",
                table: "VideoSecurityEvents",
                columns: new[] { "VideoId", "CreatedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_VideoAccessGrants_CourseId",
                table: "VideoAccessGrants",
                column: "CourseId");

            migrationBuilder.CreateIndex(
                name: "IX_VideoAccessGrants_VideoId",
                table: "VideoAccessGrants",
                column: "VideoId");

            migrationBuilder.CreateIndex(
                name: "IX_PlaybackSessions_Revoked_ExpiresAt",
                table: "PlaybackSessions",
                columns: new[] { "Revoked", "ExpiresAt" });

            migrationBuilder.CreateIndex(
                name: "IX_PlaybackSessions_UserId_VideoId",
                table: "PlaybackSessions",
                columns: new[] { "UserId", "VideoId" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_VideoSecurityEvents_Type_CreatedAt",
                table: "VideoSecurityEvents");

            migrationBuilder.DropIndex(
                name: "IX_VideoSecurityEvents_VideoId_CreatedAt",
                table: "VideoSecurityEvents");

            migrationBuilder.DropIndex(
                name: "IX_VideoAccessGrants_CourseId",
                table: "VideoAccessGrants");

            migrationBuilder.DropIndex(
                name: "IX_VideoAccessGrants_VideoId",
                table: "VideoAccessGrants");

            migrationBuilder.DropIndex(
                name: "IX_PlaybackSessions_Revoked_ExpiresAt",
                table: "PlaybackSessions");

            migrationBuilder.DropIndex(
                name: "IX_PlaybackSessions_UserId_VideoId",
                table: "PlaybackSessions");
        }
    }
}
