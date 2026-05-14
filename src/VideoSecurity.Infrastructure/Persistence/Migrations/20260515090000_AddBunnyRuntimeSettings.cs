using System;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using VideoSecurity.Infrastructure.Persistence;

#nullable disable

namespace VideoSecurity.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    [DbContext(typeof(AppDbContext))]
    [Migration("20260515090000_AddBunnyRuntimeSettings")]
    public partial class AddBunnyRuntimeSettings : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "BunnyRuntimeSettings",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    LibraryId = table.Column<long>(type: "INTEGER", nullable: false),
                    ApiKeyProtected = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: false),
                    EmbedTokenKeyProtected = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: false),
                    CdnHostname = table.Column<string>(type: "TEXT", maxLength: 255, nullable: false),
                    CdnTokenKeyProtected = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: true),
                    ApiBaseUrl = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    TusEndpoint = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    EmbedBaseUrl = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    DefaultSessionTtlSeconds = table.Column<int>(type: "INTEGER", nullable: false),
                    DefaultUploadTtlSeconds = table.Column<int>(type: "INTEGER", nullable: false),
                    LockSessionToIp = table.Column<bool>(type: "INTEGER", nullable: false),
                    PrivacyHashPepperProtected = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: true),
                    WebhookSecretProtected = table.Column<string>(type: "TEXT", maxLength: 4000, nullable: true),
                    AssumedUploadBytesPerSecond = table.Column<int>(type: "INTEGER", nullable: false),
                    WebhookEventDedupeWindowSeconds = table.Column<int>(type: "INTEGER", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    UpdatedByUserId = table.Column<string>(type: "TEXT", maxLength: 450, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_BunnyRuntimeSettings", x => x.Id);
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(name: "BunnyRuntimeSettings");
        }
    }
}