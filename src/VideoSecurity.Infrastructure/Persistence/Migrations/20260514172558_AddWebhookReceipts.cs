using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace VideoSecurity.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddWebhookReceipts : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "BunnyWebhookReceipts",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "TEXT", nullable: false),
                    BodyHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    SignatureHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    VideoGuid = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    Status = table.Column<int>(type: "INTEGER", nullable: true),
                    ReceivedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_BunnyWebhookReceipts", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_BunnyWebhookReceipts_BodyHash",
                table: "BunnyWebhookReceipts",
                column: "BodyHash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_BunnyWebhookReceipts_ReceivedAt",
                table: "BunnyWebhookReceipts",
                column: "ReceivedAt");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "BunnyWebhookReceipts");
        }
    }
}
