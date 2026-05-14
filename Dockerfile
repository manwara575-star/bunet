# syntax=docker/dockerfile:1.7
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY VideoSecurity.slnx ./
COPY Directory.Build.props ./
COPY src/ ./src/
RUN dotnet restore src/VideoSecurity.Web/VideoSecurity.Web.csproj
RUN dotnet publish src/VideoSecurity.Web/VideoSecurity.Web.csproj \
    -c Release --no-restore -o /app/publish /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app
ENV ASPNETCORE_URLS=http://+:8080 \
    DOTNET_RUNNING_IN_CONTAINER=true \
    DOTNET_EnableDiagnostics=0
EXPOSE 8080
COPY --from=build /app/publish ./
USER root
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /data /data/dp-keys && chown -R app:app /data /app
USER app
ENV DataProtection__Path=/data/dp-keys
ENTRYPOINT ["dotnet", "VideoSecurity.Web.dll"]
