CREATE OR ALTER PROCEDURE [dbo].[User_BumpAccountRevisionDateByCollectionIds]
	@CollectionIds AS [dbo].[GuidIdArray] READONLY,
	@OrganizationId UNIQUEIDENTIFIER
AS
BEGIN
	SET NOCOUNT ON

UPDATE
    U
SET
    U.[AccountRevisionDate] = GETUTCDATE()
    FROM
        [dbo].[User] U
    INNER JOIN
    	[dbo].[Collection] C ON C.[Id] IN (SELECT [Id] FROM @CollectionIds)
    INNER JOIN
    [dbo].[OrganizationUser] OU ON OU.[UserId] = U.[Id]
    LEFT JOIN
    [dbo].[CollectionUser] CU ON OU.[AccessAll] = 0 AND CU.[OrganizationUserId] = OU.[Id] AND CU.[CollectionId] = C.[Id]
    LEFT JOIN
    [dbo].[GroupUser] GU ON CU.[CollectionId] IS NULL AND OU.[AccessAll] = 0 AND GU.[OrganizationUserId] = OU.[Id]
    LEFT JOIN
    [dbo].[Group] G ON G.[Id] = GU.[GroupId]
    LEFT JOIN
    [dbo].[CollectionGroup] CG ON G.[AccessAll] = 0 AND CG.[GroupId] = GU.[GroupId] AND CG.[CollectionId] = C.[Id]
WHERE
    OU.[OrganizationId] = @OrganizationId
  AND OU.[Status] = 2 -- 2 = Confirmed
  AND (
    CU.[CollectionId] IS NOT NULL
   OR CG.[CollectionId] IS NOT NULL
   OR OU.[AccessAll] = 1
   OR G.[AccessAll] = 1
    )
END
GO

CREATE OR ALTER PROCEDURE [dbo].[Collection_CreateOrUpdateAccessForMany]
	@OrganizationId UNIQUEIDENTIFIER,
	@CollectionIds AS [dbo].[GuidIdArray] READONLY,
    @Groups AS [dbo].[CollectionAccessSelectionType] READONLY,
    @Users AS [dbo].[CollectionAccessSelectionType] READONLY
AS
BEGIN
	SET NOCOUNT ON

	 -- Groups
	;WITH [NewCollectionGroups] AS (
		SELECT
			cId.[Id] AS [CollectionId],
			cg.[Id] AS [GroupId],
			cg.[ReadOnly],
			cg.[HidePasswords],
			cg.[Manage]
		FROM
			@Groups AS cg
		CROSS JOIN -- Create a CollectionGroup record for every CollectionId
			@CollectionIds cId
		INNER JOIN
			[dbo].[Group] g ON cg.[Id] = g.[Id]
		WHERE
			g.[OrganizationId] = @OrganizationId
	)
    MERGE
    	[dbo].[CollectionGroup] as [Target]
	USING
		[NewCollectionGroups] AS [Source]
	ON
		[Target].[CollectionId] = [Source].[CollectionId]
		AND [Target].[GroupId] = [Source].[GroupId]
    -- Update the target if any values are different from the source
	WHEN MATCHED AND EXISTS(
		SELECT [Source].[ReadOnly], [Source].[HidePasswords], [Source].[Manage]
		EXCEPT
		SELECT [Target].[ReadOnly], [Target].[HidePasswords], [Target].[Manage]
	) THEN UPDATE SET
		[Target].[ReadOnly] = [Source].[ReadOnly],
		[Target].[HidePasswords] = [Source].[HidePasswords],
		[Target].[Manage] = [Source].[Manage]
	WHEN NOT MATCHED BY TARGET
		THEN INSERT
	    (
	        [CollectionId],
	        [GroupId],
	        [ReadOnly],
	        [HidePasswords],
	        [Manage]
        )
	    VALUES
		(
			[Source].[CollectionId],
			[Source].[GroupId],
			[Source].[ReadOnly],
			[Source].[HidePasswords],
			[Source].[Manage]
		);

	-- Users
	;WITH [NewCollectionUsers] AS (
		SELECT
			cId.[Id] AS [CollectionId],
			cu.[Id] AS [OrganizationUserId],
			cu.[ReadOnly],
			cu.[HidePasswords],
			cu.[Manage]
		FROM
			@Users AS cu
		CROSS JOIN -- Create a CollectionUser record for every CollectionId
			@CollectionIds cId
		INNER JOIN
			[dbo].[OrganizationUser] u ON cu.[Id] = u.[Id]
		WHERE
			u.[OrganizationId] = @OrganizationId
	)
    MERGE
    	[dbo].[CollectionUser] as [Target]
	USING
		[NewCollectionUsers] AS [Source]
	ON
		[Target].[CollectionId] = [Source].[CollectionId]
		AND [Target].[OrganizationUserId] = [Source].[OrganizationUserId]
    -- Update the target if any values are different from the source
	WHEN MATCHED AND EXISTS(
		SELECT [Source].[ReadOnly], [Source].[HidePasswords], [Source].[Manage]
		EXCEPT
		SELECT [Target].[ReadOnly], [Target].[HidePasswords], [Target].[Manage]
	) THEN UPDATE SET
		[Target].[ReadOnly] = [Source].[ReadOnly],
		[Target].[HidePasswords] = [Source].[HidePasswords],
		[Target].[Manage] = [Source].[Manage]
	WHEN NOT MATCHED BY TARGET
	    THEN INSERT
	    (
	        [CollectionId],
	        [OrganizationUserId],
	        [ReadOnly],
	        [HidePasswords],
	        [Manage]
        )
	    VALUES
		(
			[Source].[CollectionId],
			[Source].[OrganizationUserId],
			[Source].[ReadOnly],
			[Source].[HidePasswords],
			[Source].[Manage]
		);

    EXEC [dbo].[User_BumpAccountRevisionDateByCollectionIds] @CollectionIds, @OrganizationId
END
GO
