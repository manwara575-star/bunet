using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace VideoSecurity.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class PublicDemoHardening : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "AllowPublicDemo",
                table: "Videos",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<string>(
                name: "HeartbeatTokenHash",
                table: "PlaybackSessions",
                type: "TEXT",
                maxLength: 128,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "AllowPublicDemo",
                table: "Videos");

            migrationBuilder.DropColumn(
                name: "HeartbeatTokenHash",
                table: "PlaybackSessions");
        }
    }
}
