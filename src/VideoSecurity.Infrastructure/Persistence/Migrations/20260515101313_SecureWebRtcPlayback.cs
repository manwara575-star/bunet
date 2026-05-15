using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace VideoSecurity.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class SecureWebRtcPlayback : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "PlaybackProvider",
                table: "Videos",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<int>(
                name: "ProtectedMediaStatus",
                table: "Videos",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<string>(
                name: "ProtectedSourceContentType",
                table: "Videos",
                type: "TEXT",
                maxLength: 128,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ProtectedSourceOriginalFileName",
                table: "Videos",
                type: "TEXT",
                maxLength: 512,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ProtectedSourcePath",
                table: "Videos",
                type: "TEXT",
                maxLength: 1024,
                nullable: true);

            migrationBuilder.AddColumn<long>(
                name: "ProtectedSourceSizeBytes",
                table: "Videos",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "ProtectedSourceUploadedAt",
                table: "Videos",
                type: "TEXT",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_Videos_PlaybackProvider",
                table: "Videos",
                column: "PlaybackProvider");

            migrationBuilder.CreateIndex(
                name: "IX_Videos_ProtectedMediaStatus",
                table: "Videos",
                column: "ProtectedMediaStatus");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Videos_PlaybackProvider",
                table: "Videos");

            migrationBuilder.DropIndex(
                name: "IX_Videos_ProtectedMediaStatus",
                table: "Videos");

            migrationBuilder.DropColumn(
                name: "PlaybackProvider",
                table: "Videos");

            migrationBuilder.DropColumn(
                name: "ProtectedMediaStatus",
                table: "Videos");

            migrationBuilder.DropColumn(
                name: "ProtectedSourceContentType",
                table: "Videos");

            migrationBuilder.DropColumn(
                name: "ProtectedSourceOriginalFileName",
                table: "Videos");

            migrationBuilder.DropColumn(
                name: "ProtectedSourcePath",
                table: "Videos");

            migrationBuilder.DropColumn(
                name: "ProtectedSourceSizeBytes",
                table: "Videos");

            migrationBuilder.DropColumn(
                name: "ProtectedSourceUploadedAt",
                table: "Videos");
        }
    }
}
