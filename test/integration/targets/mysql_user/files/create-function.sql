USE foo;
DELIMITER ;;
CREATE FUNCTION `function` () RETURNS tinyint(4)
BEGIN
  DECLARE NAME_FOUND tinyint DEFAULT 0;
  RETURN NAME_FOUND;
END;;
DELIMITER ;
