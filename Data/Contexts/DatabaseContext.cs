using Microsoft.EntityFrameworkCore;
using WebAppCap7.Models;

public class DatabaseContext : DbContext
{
    public DatabaseContext(DbContextOptions<DatabaseContext> options) : base(options)
    {
    }

    public DbSet<QualidadeArModel> QualidadeAr { get; set; }
    public DbSet<User> Users { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // Configuración de la secuencia para T_QUALIDADE_AR
        modelBuilder.HasSequence<int>("SEQ_QUALIDADE_AR")
            .StartsAt(1)
            .IncrementsBy(1);

        modelBuilder.Entity<QualidadeArModel>(entity =>
        {
            entity.ToTable("T_QUALIDADE_AR");

            entity.Property(e => e.Id)
                .HasColumnName("ID_DADO")
                .HasDefaultValueSql("NEXT VALUE FOR SEQ_QUALIDADE_AR")
                .IsRequired();

            entity.Property(e => e.IdEstacao)
                .HasColumnName("ID_ESTACAO")
                .IsRequired();

            entity.Property(e => e.DataHora)
                .HasColumnName("DATA_HORA")
                .HasColumnType("TIMESTAMP")
                .IsRequired();

            entity.Property(e => e.NivelPm25)
                .HasColumnName("NIVEL_PM2_5")
                .HasColumnType("FLOAT");

            entity.Property(e => e.NivelPm10)
                .HasColumnName("NIVEL_PM10")
                .HasColumnType("FLOAT");

            entity.Property(e => e.ConfigAlertasIdConfiguracao)
                .HasColumnName("CONFIG_ALERTAS_ID_CONFIGURACAO");
        });

        // Configuración de la secuencia para TB_USERS
        modelBuilder.HasSequence<int>("SEQ_USERS")
            .StartsAt(1)
            .IncrementsBy(1);

        modelBuilder.Entity<User>(entity =>
        {
            entity.ToTable("TB_USERS");

            entity.HasKey(e => e.UserId)
                .HasName("TB_USERS_PK");

            entity.Property(e => e.UserId)
                .HasColumnName("USER_ID")
                .HasDefaultValueSql("NEXT VALUE FOR SEQ_USERS")
                .IsRequired();

            entity.Property(e => e.Email)
                .HasColumnName("EMAIL")
                .HasMaxLength(100)
                .IsRequired();

            entity.HasIndex(e => e.Email)
                .IsUnique()
                .HasDatabaseName("TB_USERS_UNIQUE");

            entity.Property(e => e.PasswordHash) // Alteraré el nombre
                .HasColumnName("PASSWORD")
                .HasMaxLength(40)
                .IsRequired();

            entity.Property(e => e.Role)
                .HasColumnName("ROLE")
                .HasMaxLength(100)
                .HasDefaultValueSql("'USER'");
        });
    }
}
