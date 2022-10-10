IF NOT EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'%table_name%') AND type in (N'U'))
begin
  CREATE TABLE %table_name% (
  id int IDENTITY(1,1),
  ptype varchar(255) NOT NULL,
  v0 varchar(255) DEFAULT NULL,
  v1 varchar(255) DEFAULT NULL,
  v2 varchar(255) DEFAULT NULL,
  v3 varchar(255) DEFAULT NULL,
  v4 varchar(255) DEFAULT NULL,
  v5 varchar(255) DEFAULT NULL
)
end;
