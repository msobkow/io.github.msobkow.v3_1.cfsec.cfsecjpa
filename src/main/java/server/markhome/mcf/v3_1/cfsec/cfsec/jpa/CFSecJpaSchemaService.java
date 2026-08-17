// Description: Java 25 Spring JPA Service for CFSec

/*
 *	server.markhome.mcf.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow mark.sobkow@gmail.com
 *	
 *	These files are part of Mark's Code Fractal CFSec.
 *	
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *	
 *	http://www.apache.org/licenses/LICENSE-2.0
 *	
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 *	
 */

package server.markhome.mcf.v3_1.cfsec.cfsec.jpa;

import java.io.Serializable;
import java.math.*;
import java.net.InetAddress;
import java.time.*;
import java.util.*;
import jakarta.persistence.*;
import server.markhome.mcf.v3_1.cflib.*;
import server.markhome.mcf.v3_1.cflib.dbutil.*;
import server.markhome.mcf.v3_1.cflib.keyhash.*;
import server.markhome.mcf.v3_1.cflib.xml.CFLibXmlUtil;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.text.StringEscapeUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import server.markhome.mcf.v3_1.cfsec.cfsecpub.*;
import server.markhome.mcf.v3_1.cfsec.cfsecpubobj.*;
import server.markhome.mcf.v3_1.cfsec.cfsec.*;
import server.markhome.mcf.v3_1.cfsec.cfsecpubobj.*;

/**
 *	Services for schema CFSec defined in server.markhome.mcf.v3_1.cfsec.cfsec.jpa
 *	using the CFSec*Repository objects to access the data directly, bypassing normal application security for the bootstrap and login processing.
 */
@Service("cfsec31JpaSchemaService")
public class CFSecJpaSchemaService {

	@Autowired
	@Qualifier("cfsec31EntityManagerFactory")
	private LocalContainerEntityManagerFactoryBean cfsec31EntityManagerFactory;
	@Autowired
	private CFSecJpaClusterService clusterService;

	@Autowired
	private CFSecJpaTenantService tenantService;

	@Autowired
	private CFSecJpaTableInfoService tableinfoService;

	@Autowired
	private CFSecJpaISOCcyService isoccyService;

	@Autowired
	private CFSecJpaISOCtryService isoctryService;

	@Autowired
	private CFSecJpaISOCtryCcyService isoctryccyService;

	@Autowired
	private CFSecJpaISOCtryLangService isoctrylangService;

	@Autowired
	private CFSecJpaISOLangService isolangService;

	@Autowired
	private CFSecJpaISOTZoneService isotzoneService;

	@Autowired
	private CFSecJpaSecUserService secuserService;

	@Autowired
	private CFSecJpaSecUserPasswordService secuserpasswordService;

	@Autowired
	private CFSecJpaSecUserEMConfService secuseremconfService;

	@Autowired
	private CFSecJpaSecUserPWResetService secuserpwresetService;

	@Autowired
	private CFSecJpaSecUserPWHistoryService secuserpwhistoryService;

	@Autowired
	private CFSecJpaSecSysGrpService secsysgrpService;

	@Autowired
	private CFSecJpaSecSysGrpIncService secsysgrpincService;

	@Autowired
	private CFSecJpaSecSysGrpMembService secsysgrpmembService;

	@Autowired
	private CFSecJpaSecClusGrpService secclusgrpService;

	@Autowired
	private CFSecJpaSecClusGrpMembService secclusgrpmembService;

	@Autowired
	private CFSecJpaSecTentGrpService sectentgrpService;

	@Autowired
	private CFSecJpaSecTentGrpMembService sectentgrpmembService;

	@Autowired
	private CFSecJpaSecSysRoleService secsysroleService;

	@Autowired
	private CFSecJpaSecSysRoleEnablesService secsysroleenablesService;

	@Autowired
	private CFSecJpaSecSysRoleMembService secsysrolemembService;

	@Autowired
	private CFSecJpaSecClusRoleService secclusroleService;

	@Autowired
	private CFSecJpaSecClusRoleMembService secclusrolemembService;

	@Autowired
	private CFSecJpaSecTentRoleService sectentroleService;

	@Autowired
	private CFSecJpaSecTentRoleMembService sectentrolemembService;

	@Autowired
	private CFSecJpaSecSessionService secsessionService;

	@Autowired
	private CFSecJpaSysClusterService sysclusterService;


	public void bootstrapSchema(CFSecPubTableData tableData[]) {
		bootstrapSecurity();
		bootstrapAllTablesSecurity(tableData);
	}

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void bootstrapSecurity() {
		CFSecJpaSysCluster sysCluster;
		CFLibDbKeyHash256 systemClusterID;
		CFSecJpaCluster systemCluster;
		CFSecJpaSecUser systemUser;
		CFLibDbKeyHash256 systemUID;
		CFSecJpaSecUser systemAdminUser;
		CFLibDbKeyHash256 systemAdminUID;
		CFSecJpaSecSession bootstrapSession;
		CFLibDbKeyHash256 bootstrapSessionID;
		CFSecJpaTenant systemTenant;
		CFLibDbKeyHash256 systemTenantID;
		CFSecJpaSecSysGrp secSystemAdminGroup;
		CFLibDbKeyHash256 secSystemAdminGroupID;
		CFSecJpaSecSysGrpMemb secSystemAdminGroupMembSystemAdmin;
		CFSecJpaSecSysGrp secSysGroupPublic;
		CFLibDbKeyHash256 secSysGroupPublicID;
		CFSecJpaSecSysGrpInc secSysGroupPublicIncSystemAdmin;
		systemUser = secuserService.findByULoginIdx("system");
		if (systemUser != null) {
			systemUID = systemUser.getRequiredSecUserId();
			ICFSecSchema.setSystemId(systemUID);

			ICFSecSchema.setAuthorizationCallback( new ICFSecAuthorizationCallback() {
				CFSecAuthorization auth = new CFSecAuthorization();
				@Override
				public ICFSecAuthorization getEffectiveAuthorization() {
					return(auth);
				}
			});
			CFSecAuthorization auth = (CFSecAuthorization)ICFSecSchema.getAuthorizationCallback().getEffectiveAuthorization();
			auth.setAuthUuid6(CFLibUuid6.generateUuid6());
			auth.setSecUserId(systemUID);
		
			systemAdminUser = secuserService.findByULoginIdx("systemadmin");
			if (systemAdminUser == null) {
				throw new CFLibNullArgumentException(getClass(), "bootstrapSecurity", 0, "findByULoginIdx('systemadmin')");
			}
			systemAdminUID = systemAdminUser.getRequiredSecUserId();

			List<CFSecJpaSysCluster> sysClusters = sysclusterService.findAll();
			if (sysClusters != null && sysClusters.size() == 1) {
				sysCluster = sysClusters.get(0);
				systemClusterID = sysCluster.getRequiredClusterId();
				if(systemClusterID == null || systemClusterID.isNull()) {
					throw new CFLibNullArgumentException(getClass(), "bootstrapSecurity", 0, "systemClusterID");
				}
				systemCluster = clusterService.find(systemClusterID);
				if (systemCluster == null) {
					throw new CFLibNullArgumentException(getClass(), "bootstrapSecurity", 0, "systemCluster");
				}
				systemTenant = tenantService.findByUNameIdx(systemClusterID, "system");
				if( systemTenant == null) {
					systemTenantID = null;
					throw new CFLibNullArgumentException(getClass(), "bootstrapSecurity", 0, "systemTenant");
				}
				else {
					systemTenantID = systemTenant.getPKey();
				}
				bootstrapSession = secsessionService.findByStartIdx(systemUID, systemCluster.getCreatedAt());
				if (bootstrapSession == null) {
					List<CFSecJpaSecSession> sessions = secsessionService.findBySecUserIdx(systemUID);
					if (sessions != null) {
						for (CFSecJpaSecSession cursess: sessions) {
							if (bootstrapSession == null || (bootstrapSession != null && (cursess.getRequiredStart().compareTo(bootstrapSession.getRequiredStart()) < 0))) {
								bootstrapSession = cursess;
							}
						}
					}
					if (bootstrapSession == null) {
						throw new CFLibNullArgumentException(getClass(), "bootstrapSecurity", 0, "bootstrapSession");
					}
				}
				bootstrapSessionID = bootstrapSession.getPKey();

				auth.setSecSessionId(bootstrapSessionID);
				auth.setSecClusterId(systemClusterID);
				auth.setSecTenantId(systemTenantID);

				secSystemAdminGroup = (CFSecJpaSecSysGrp)(secsysgrpService.findByUNameIdx( "systemadmin"));
				if (secSystemAdminGroup == null) {
					throw new CFLibNullArgumentException(getClass(), "bootstrapSecurity", 0, "secSystemAdminGroup");
				}
				secSystemAdminGroupID = secSystemAdminGroup.getRequiredSecSysGrpId();

				secSysGroupPublic = (CFSecJpaSecSysGrp)(secsysgrpService.findByUNameIdx( "public"));
				if (secSysGroupPublic == null) {
					throw new CFLibNullArgumentException(getClass(), "bootstrapSecurity", 0, "secSysGroupPublic");
				}
				secSysGroupPublicID = secSysGroupPublic.getRequiredSecSysGrpId();

				secSystemAdminGroupMembSystemAdmin = (CFSecJpaSecSysGrpMemb)(secsysgrpmembService.find(secSystemAdminGroupID, systemUser.getRequiredLoginId()));
				if (secSystemAdminGroupMembSystemAdmin == null) {
					throw new CFLibNullArgumentException(getClass(), "bootstrapSecurity", 0, "secSystemAdminGroupMembSystemAdmin");
				}

				secSysGroupPublicIncSystemAdmin = (CFSecJpaSecSysGrpInc)(secsysgrpincService.find(secSysGroupPublicID, secSystemAdminGroup.getRequiredName()));
				if (secSysGroupPublicIncSystemAdmin == null) {
					throw new CFLibNullArgumentException(getClass(), "bootstrapSecurity", 0, "secSysGroupPublicIncSystemAdmin");
				}
			}
			else {
				throw new CFLibNullArgumentException(getClass(), "bootstrapSecurity", 0, "SysClusterSingleton");
			}
		}
		else {
			systemUID = null;
			systemAdminUID = null;
			systemAdminUser = null;
			sysCluster = null;
			systemCluster = null;
			systemClusterID = null;
			bootstrapSession = null;
			bootstrapSessionID = null;
			systemTenant = null;
			systemTenantID = null;
			secSystemAdminGroup = null;
			secSystemAdminGroupID = null;
			secSystemAdminGroupMembSystemAdmin = null;
			secSysGroupPublic = null;
			secSysGroupPublicID = null;
			secSysGroupPublicIncSystemAdmin = null;
		}
		LocalDateTime now = LocalDateTime.now();
		if (systemUID == null || systemUID.isNull()) {
			systemUID = new CFLibDbKeyHash256(0);
		}
		if (systemAdminUID == null || systemAdminUID.isNull()) {
			systemAdminUID = new CFLibDbKeyHash256(0);
		}
		if (bootstrapSessionID == null || bootstrapSessionID.isNull()) {
			bootstrapSessionID = new CFLibDbKeyHash256(0);
		}
		if (systemClusterID == null || systemClusterID.isNull()) {
			systemClusterID = new CFLibDbKeyHash256(0);
		}
		if (systemTenantID == null || systemTenantID.isNull()) {
			systemTenantID = new CFLibDbKeyHash256(0);
		}
		if (secSystemAdminGroupID == null || secSystemAdminGroupID.isNull()) {
			secSystemAdminGroupID = new CFLibDbKeyHash256(0);
		}
		if (secSysGroupPublicID == null || secSysGroupPublicID.isNull()) {
			secSysGroupPublicID = new CFLibDbKeyHash256(0);
		}
		if (ICFSecSchema.getSysClusterId() == null || ICFSecSchema.getSysClusterId().isNull()) {
			ICFSecSchema.setSysClusterId(systemClusterID);
		}
		else if ( ! ICFSecSchema.getSysClusterId().equals( systemClusterID )) {
			throw new CFLibInvalidArgumentException(getClass(), "bootstrapSecurity", "Previously set system cluster id disagrees with new system cluster id", "Previously set system cluster id disagrees with new system cluster id");
		}
		if (ICFSecSchema.getSysTenantId() == null || ICFSecSchema.getSysTenantId().isNull()) {
			ICFSecSchema.setSysTenantId(systemTenantID);
		}
		else if ( ! ICFSecSchema.getSysTenantId().equals( systemTenantID )) {
			throw new CFLibInvalidArgumentException(getClass(), "bootstrapSecurity", "Previously set system tenant id disagrees with new system tenant id", "Previously set system tenant id disagrees with new system tenant id");
		}
		if (!systemUID.equals(ICFSecSchema.getSystemId())) {
			ICFSecSchema.setSystemId(systemUID);
		}

		String fqdn;
		try {
			InetAddress localHost = InetAddress.getLocalHost();
			fqdn = localHost.getCanonicalHostName();
		} catch (java.net.UnknownHostException e) {
			fqdn = "localhost";
		}
		
		ICFSecSchema.setAuthorizationCallback( new ICFSecAuthorizationCallback() {
			CFSecAuthorization auth = new CFSecAuthorization();
			@Override
			public ICFSecAuthorization getEffectiveAuthorization() {
				return(auth);
			}
		});
		CFSecAuthorization auth = (CFSecAuthorization)ICFSecSchema.getAuthorizationCallback().getEffectiveAuthorization();
		auth.setAuthUuid6(CFLibUuid6.generateUuid6());
		auth.setSecUserId(systemUID);
		auth.setSecSessionId(bootstrapSessionID);
		auth.setSecClusterId(systemClusterID);
		auth.setSecTenantId(systemTenantID);

		if (systemCluster == null) {
			systemCluster = new CFSecJpaCluster();
			systemCluster.setRequiredRevision(1);
			systemCluster.setRequiredId(systemClusterID);
			systemCluster.setCreatedByUserId(systemUID);
			systemCluster.setUpdatedByUserId(systemUID);
			systemCluster.setCreatedAt(now);
			systemCluster.setUpdatedAt(now);
			systemCluster.setRequiredFullDomName(fqdn);
			systemCluster.setRequiredDescription("system");
			systemCluster = clusterService.create(systemCluster);
			systemClusterID = systemCluster.getPKey();
		}

		if (systemUser == null) {
			systemUser = new CFSecJpaSecUser();
			systemUser.setRequiredRevision(1);
			systemUser.setCreatedByUserId(systemUID);
			systemUser.setUpdatedByUserId(systemUID);
			systemUser.setCreatedAt(now);
			systemUser.setUpdatedAt(now);
			systemUser.setRequiredSecUserId(systemUID);
			systemUser.setRequiredLoginId("system");
			systemUser.setRequiredEMailAddress("system@" + fqdn);
			systemUser.setRequiredAccountStatus(ICFSecPubSchema.SecAccountStatusEnum.System);
			systemUser = secuserService.create(systemUser);
			systemUID = systemUser.getPKey();
		}

		if (systemAdminUser == null) {
			systemAdminUser = new CFSecJpaSecUser();
			systemAdminUser.setRequiredRevision(1);
			systemAdminUser.setCreatedByUserId(systemUID);
			systemAdminUser.setUpdatedByUserId(systemUID);
			systemAdminUser.setCreatedAt(now);
			systemAdminUser.setUpdatedAt(now);
			systemAdminUser.setRequiredSecUserId(systemAdminUID);
			systemAdminUser.setRequiredLoginId("systemadmin");
			systemAdminUser.setRequiredEMailAddress("systemadmin@" + fqdn);
			systemAdminUser.setRequiredAccountStatus(ICFSecPubSchema.SecAccountStatusEnum.ResettingPassword);
			systemAdminUser = secuserService.create(systemAdminUser);
			systemAdminUID = systemAdminUser.getPKey();
			
			CFSecJpaSecUserPassword systemAdminUserPassword = secuserpasswordService.find(systemAdminUID);
			if (systemAdminUserPassword == null) {
				systemAdminUserPassword = new CFSecJpaSecUserPassword();
				systemAdminUserPassword.setRequiredRevision(1);
				systemAdminUserPassword.setPKey(systemAdminUID);
				systemAdminUserPassword.setRequiredContainerUser(systemAdminUser);
				systemAdminUserPassword.setRequiredPWSetStamp(now);
				systemAdminUserPassword.setRequiredPasswordHash(ICFSecSchema.getPasswordHash("ChangeOnInstall"));
				systemAdminUserPassword = secuserpasswordService.create(systemAdminUserPassword);
			}
		}

		if (systemTenant == null) {
			systemTenant = new CFSecJpaTenant();
			systemTenant.setRequiredRevision(1);
			systemTenant.setRequiredId(systemTenantID);
			systemTenant.setCreatedByUserId(systemUID);
			systemTenant.setUpdatedByUserId(systemUID);
			systemTenant.setCreatedAt(now);
			systemTenant.setUpdatedAt(now);
			systemTenant.setRequiredContainerCluster(systemClusterID);
			systemTenant.setRequiredTenantName("system");
			systemTenant = tenantService.create(systemTenant);
			systemTenantID = systemTenant.getPKey();
		}

		if (bootstrapSession == null) {
			bootstrapSession = new CFSecJpaSecSession();
			bootstrapSession.setRequiredRevision(1);
			bootstrapSession.setRequiredSecSessionId(bootstrapSessionID);
			bootstrapSession.setRequiredSecUserId(systemUID);
			bootstrapSession.setOptionalSecProxyId(systemUID);
			bootstrapSession.setRequiredStart(now);
			bootstrapSession.setOptionalFinish(null);
			bootstrapSession = secsessionService.create(bootstrapSession);
		}

		if (sysCluster == null) {
			sysCluster = new CFSecJpaSysCluster();
			sysCluster.setRequiredContainerCluster(systemClusterID);
			sysCluster = sysclusterService.create(sysCluster);
		}

		if (secSystemAdminGroup == null) {
			secSystemAdminGroup = new CFSecJpaSecSysGrp();
			secSystemAdminGroup.setPKey(secSystemAdminGroupID);
			secSystemAdminGroup.setRequiredRevision(1);
			secSystemAdminGroup.setCreatedAt(now);
			secSystemAdminGroup.setCreatedByUserId(systemUID);
			secSystemAdminGroup.setUpdatedAt(now);
			secSystemAdminGroup.setUpdatedByUserId(systemUID);
			secSystemAdminGroup.setRequiredName("systemadmin");
			secSystemAdminGroup.setRequiredSecLevel(ICFSecPubSchema.SecLevelEnum.System);
			secSystemAdminGroup.setRequiredSecSysGrpId(secSystemAdminGroupID);
			secSystemAdminGroup = (CFSecJpaSecSysGrp)(secsysgrpService.create(secSystemAdminGroup));
			secSystemAdminGroupID = secSystemAdminGroup.getRequiredSecSysGrpId();
		}

		if (secSystemAdminGroupMembSystemAdmin == null) {
			secSystemAdminGroupMembSystemAdmin = new CFSecJpaSecSysGrpMemb();
			secSystemAdminGroupMembSystemAdmin.setRequiredRevision(1);
			secSystemAdminGroupMembSystemAdmin.setRequiredContainerGroup(secSystemAdminGroupID);
			secSystemAdminGroupMembSystemAdmin.setRequiredParentUser(systemAdminUser.getRequiredLoginId());
			secSystemAdminGroupMembSystemAdmin = (CFSecJpaSecSysGrpMemb)(secsysgrpmembService.create(secSystemAdminGroupMembSystemAdmin));
		}

		if (secSysGroupPublic == null) {
			secSysGroupPublic = new CFSecJpaSecSysGrp();
			secSysGroupPublic.setRequiredRevision(1);
			secSysGroupPublic.setCreatedAt(now);
			secSysGroupPublic.setCreatedByUserId(systemUID);
			secSysGroupPublic.setUpdatedAt(now);
			secSysGroupPublic.setUpdatedByUserId(systemUID);
			secSysGroupPublic.setRequiredName("public");
			secSysGroupPublic.setRequiredSecLevel(ICFSecPubSchema.SecLevelEnum.System);
			secSysGroupPublic.setRequiredSecSysGrpId(secSysGroupPublicID);
			secSysGroupPublic = (CFSecJpaSecSysGrp)(secsysgrpService.create(secSysGroupPublic));
			secSysGroupPublicID = secSysGroupPublic.getRequiredSecSysGrpId();
		}

		if (secSysGroupPublicIncSystemAdmin == null) {
			secSysGroupPublicIncSystemAdmin = new CFSecJpaSecSysGrpInc();
			secSysGroupPublicIncSystemAdmin.setRequiredContainerGroup(secSysGroupPublicID);
			secSysGroupPublicIncSystemAdmin.setCreatedAt(now);
			secSysGroupPublicIncSystemAdmin.setCreatedByUserId(systemUID);
			secSysGroupPublicIncSystemAdmin.setUpdatedAt(now);
			secSysGroupPublicIncSystemAdmin.setUpdatedByUserId(systemUID);
			secSysGroupPublicIncSystemAdmin.setRequiredParentSubGroup(secSystemAdminGroup.getRequiredName());
			secSysGroupPublicIncSystemAdmin.setRequiredRevision(1);
			secSysGroupPublicIncSystemAdmin = (CFSecJpaSecSysGrpInc)(secsysgrpincService.create(secSysGroupPublicIncSystemAdmin));
		}

		if (bootstrapSession != null && bootstrapSessionID != null && !bootstrapSessionID.isNull() && bootstrapSession.getOptionalFinish() == null) {
			bootstrapSession.setOptionalFinish(LocalDateTime.now());
			bootstrapSession = secsessionService.update(bootstrapSession);
			ICFSecSchema.setAuthorizationCallback( new ICFSecAuthorizationCallback() {
				@Override
				public ICFSecAuthorization getEffectiveAuthorization() {
					return(null);
				}
			});
		}
	}

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void bootstrapTableSecurity(ICFSecAuthorization auth,
		LocalDateTime now,
		String tableName,
		boolean hasHistory,
		boolean isMutable,
		String secScope,
		ICFSecSecSysGrp secSysGroupPublic,
		ICFSecSecSysGrp secSystemAdminGroup,
		ICFSecSecClusGrp secSysClusGroupSysAdmin,
		ICFSecSecTentGrp secSysTentGroupSysAdmin )
	{
		ICFSecPubSchema.SecLevelEnum level;
		if (secScope.equalsIgnoreCase("global")) {
			level = ICFSecPubSchema.SecLevelEnum.Global;
		}
		else if (secScope.toLowerCase().startsWith("cluster")) {
			level = ICFSecPubSchema.SecLevelEnum.Cluster;
		}
		else if (secScope.toLowerCase().startsWith("tenant")) {
			level = ICFSecPubSchema.SecLevelEnum.Tenant;
		}
		else {
			level = ICFSecPubSchema.SecLevelEnum.System;
		}
			
		String lowerTableName = tableName.toLowerCase();
		String createPermName = "create" + lowerTableName;
		String readPermName = "read" + lowerTableName;
		String updatePermName = "update" + lowerTableName;
		String deletePermName = "delete" + lowerTableName;
		String restorePermName = "restore" + lowerTableName;
		String mutatePermName = "mutate" + lowerTableName;
		String systemGroup = secSystemAdminGroup.getRequiredName();
		String sysclusadminGroup = secSysClusGroupSysAdmin.getRequiredName();
		String systentadminGroup = secSysTentGroupSysAdmin.getRequiredName();
		String publicGroup = secSysGroupPublic.getRequiredName();
		
		ICFSecSecSysGrp secGroupCreate;
		CFLibDbKeyHash256 secGroupCreateID;
		ICFSecSecSysGrpInc secGroupCreateIncSystemAdmin;
		ICFSecSecSysGrp secGroupRead;
		CFLibDbKeyHash256 secGroupReadID;
		ICFSecSecSysGrpInc secGroupReadIncSystemAdmin;
		ICFSecSecSysGrpInc secGroupReadIncPublic;
		ICFSecSecSysGrp secGroupUpdate;
		CFLibDbKeyHash256 secGroupUpdateID;
		ICFSecSecSysGrpInc secGroupUpdateIncSystemAdmin;
		ICFSecSecSysGrp secGroupDelete;
		CFLibDbKeyHash256 secGroupDeleteID;
		ICFSecSecSysGrpInc secGroupDeleteIncSystemAdmin;
		ICFSecSecSysGrp secGroupRestore;
		CFLibDbKeyHash256 secGroupRestoreID;
		ICFSecSecSysGrpInc secGroupRestoreIncSystemAdmin;
		ICFSecSecSysGrp secGroupMutate;
		CFLibDbKeyHash256 secGroupMutateID;
		ICFSecSecSysGrpInc secGroupMutateIncSystemAdmin;

		ICFSecSecClusGrp csecGroupCreate;
		CFLibDbKeyHash256 csecGroupCreateID;
		ICFSecSecClusGrp csecGroupRead;
		CFLibDbKeyHash256 csecGroupReadID;
		ICFSecSecClusGrp csecGroupUpdate;
		CFLibDbKeyHash256 csecGroupUpdateID;
		ICFSecSecClusGrp csecGroupDelete;
		CFLibDbKeyHash256 csecGroupDeleteID;
		ICFSecSecClusGrp csecGroupRestore;
		CFLibDbKeyHash256 csecGroupRestoreID;
		ICFSecSecClusGrp csecGroupMutate;
		CFLibDbKeyHash256 csecGroupMutateID;
		
		ICFSecSecTentGrp tsecGroupCreate;
		CFLibDbKeyHash256 tsecGroupCreateID;
		ICFSecSecTentGrp tsecGroupRead;
		CFLibDbKeyHash256 tsecGroupReadID;
		ICFSecSecTentGrp tsecGroupUpdate;
		CFLibDbKeyHash256 tsecGroupUpdateID;
		ICFSecSecTentGrp tsecGroupDelete;
		CFLibDbKeyHash256 tsecGroupDeleteID;
		ICFSecSecTentGrp tsecGroupRestore;
		CFLibDbKeyHash256 tsecGroupRestoreID;
		ICFSecSecTentGrp tsecGroupMutate;
		CFLibDbKeyHash256 tsecGroupMutateID;

		secGroupCreate = ICFSecSchema.getBackingCFSec().getTableSecSysGrp().readDerivedByUNameIdx(auth, createPermName);
		if (secGroupCreate != null) {
			secGroupCreateID = secGroupCreate.getRequiredSecSysGrpId();
			secGroupCreateIncSystemAdmin = ICFSecSchema.getBackingCFSec().getTableSecSysGrpInc().readDerived(auth, secGroupCreateID, systemGroup);
		}
		else {
			secGroupCreateID = null;
			secGroupCreateIncSystemAdmin = null;
		}

		secGroupRead = ICFSecSchema.getBackingCFSec().getTableSecSysGrp().readDerivedByUNameIdx(auth, readPermName);
		if (secGroupRead != null) {
			secGroupReadID = secGroupRead.getRequiredSecSysGrpId();
			secGroupReadIncSystemAdmin = ICFSecSchema.getBackingCFSec().getTableSecSysGrpInc().readDerived(auth, secGroupReadID, systemGroup);
		}
		else {
			secGroupReadID = null;
			secGroupReadIncSystemAdmin = null;
		}

		if (secGroupRead != null && level == ICFSecPubSchema.SecLevelEnum.Global) {
			secGroupReadIncPublic = ICFSecSchema.getBackingCFSec().getTableSecSysGrpInc().readDerived(auth, secGroupReadID, publicGroup);
		}
		else {
			secGroupReadIncPublic = null;
		}

		secGroupUpdate = ICFSecSchema.getBackingCFSec().getTableSecSysGrp().readDerivedByUNameIdx(auth, updatePermName);
		if (secGroupUpdate != null) {
			secGroupUpdateID = secGroupUpdate.getRequiredSecSysGrpId();
			secGroupUpdateIncSystemAdmin = ICFSecSchema.getBackingCFSec().getTableSecSysGrpInc().readDerived(auth, secGroupUpdateID, systemGroup);
		}
		else {
			secGroupUpdateID = null;
			secGroupUpdateIncSystemAdmin = null;
		}

		secGroupDelete = ICFSecSchema.getBackingCFSec().getTableSecSysGrp().readDerivedByUNameIdx(auth, deletePermName);
		if (secGroupDelete != null) {
			secGroupDeleteID = secGroupDelete.getRequiredSecSysGrpId();
			secGroupDeleteIncSystemAdmin = ICFSecSchema.getBackingCFSec().getTableSecSysGrpInc().readDerived(auth, secGroupDeleteID, systemGroup);
		}
		else {
			secGroupDeleteID = null;
			secGroupDeleteIncSystemAdmin = null;
		}
		
		if (hasHistory) {
			secGroupRestore = ICFSecSchema.getBackingCFSec().getTableSecSysGrp().readDerivedByUNameIdx(auth, restorePermName);
			if (secGroupRestore != null) {
				secGroupRestoreID = secGroupRestore.getRequiredSecSysGrpId();
				secGroupRestoreIncSystemAdmin = ICFSecSchema.getBackingCFSec().getTableSecSysGrpInc().readDerived(auth, secGroupRestoreID, systemGroup);
			}
			else {
				secGroupRestoreID = null;
				secGroupRestoreIncSystemAdmin = null;
			}
		}
		else {
			secGroupRestore = null;
			secGroupRestoreID = null;
			secGroupRestoreIncSystemAdmin = null;
		}
		
		if (isMutable) {
			secGroupMutate = ICFSecSchema.getBackingCFSec().getTableSecSysGrp().readDerivedByUNameIdx(auth, mutatePermName);
			if (secGroupMutate != null) {
				secGroupMutateID = secGroupMutate.getRequiredSecSysGrpId();
				secGroupMutateIncSystemAdmin = ICFSecSchema.getBackingCFSec().getTableSecSysGrpInc().readDerived(auth, secGroupMutateID, systemGroup);
			}
			else {
				secGroupMutateID = null;
				secGroupMutateIncSystemAdmin = null;
			}
		}
		else {
			secGroupMutate = null;
			secGroupMutateID = null;
			secGroupMutateIncSystemAdmin = null;
		}

		if (secGroupCreateID == null || secGroupCreateID.isNull()) {
			secGroupCreateID = new CFLibDbKeyHash256(0);
		}
		if (secGroupReadID == null || secGroupReadID.isNull()) {
			secGroupReadID = new CFLibDbKeyHash256(0);
		}
		if (secGroupUpdateID == null || secGroupUpdateID.isNull()) {
			secGroupUpdateID = new CFLibDbKeyHash256(0);
		}
		if (secGroupDeleteID == null || secGroupDeleteID.isNull()) {
			secGroupDeleteID = new CFLibDbKeyHash256(0);
		}
		if (hasHistory) {
			if (secGroupRestoreID == null || secGroupRestoreID.isNull()) {
				secGroupRestoreID = new CFLibDbKeyHash256(0);
			}
		}
		if (isMutable) {
			if (secGroupMutateID == null || secGroupMutateID.isNull()) {
				secGroupMutateID = new CFLibDbKeyHash256(0);
			}
		}

		if (secGroupCreate == null) {
			secGroupCreate = ICFSecSchema.getBackingCFSec().getCFSecFactory().getFactorySecSysGrp().newRec();
			secGroupCreate.setRequiredRevision(1);
			secGroupCreate.setCreatedAt(now);
			secGroupCreate.setCreatedByUserId(auth.getSecUserId());
			secGroupCreate.setUpdatedAt(now);
			secGroupCreate.setUpdatedByUserId(auth.getSecUserId());
			secGroupCreate.setRequiredName(createPermName);
			secGroupCreate.setRequiredSecLevel(level);
			secGroupCreate.setRequiredSecSysGrpId(secGroupCreateID);
			secGroupCreate = ICFSecSchema.getBackingCFSec().getTableSecSysGrp().createSecSysGrp(auth, secGroupCreate);
			secGroupCreateID = secGroupCreate.getRequiredSecSysGrpId();
		}

		if (secGroupCreateIncSystemAdmin == null) {
			secGroupCreateIncSystemAdmin = ICFSecSchema.getBackingCFSec().getCFSecFactory().getFactorySecSysGrpInc().newRec();
			secGroupCreateIncSystemAdmin.setRequiredRevision(1);
			secGroupCreateIncSystemAdmin.setCreatedAt(now);
			secGroupCreateIncSystemAdmin.setCreatedByUserId(auth.getSecUserId());
			secGroupCreateIncSystemAdmin.setUpdatedAt(now);
			secGroupCreateIncSystemAdmin.setUpdatedByUserId(auth.getSecUserId());
			secGroupCreateIncSystemAdmin.setRequiredContainerGroup(secGroupCreateID);
			secGroupCreateIncSystemAdmin.setRequiredParentSubGroup(systemGroup);
			secGroupCreateIncSystemAdmin = ICFSecSchema.getBackingCFSec().getTableSecSysGrpInc().createSecSysGrpInc(auth, secGroupCreateIncSystemAdmin);
		}

		if (secGroupRead == null) {
			secGroupRead = ICFSecSchema.getBackingCFSec().getCFSecFactory().getFactorySecSysGrp().newRec();
			secGroupRead.setRequiredRevision(1);
			secGroupRead.setCreatedAt(now);
			secGroupRead.setCreatedByUserId(auth.getSecUserId());
			secGroupRead.setUpdatedAt(now);
			secGroupRead.setUpdatedByUserId(auth.getSecUserId());
			secGroupRead.setRequiredName(readPermName);
			secGroupRead.setRequiredSecLevel(level);
			secGroupRead.setRequiredSecSysGrpId(secGroupReadID);
			secGroupRead = ICFSecSchema.getBackingCFSec().getTableSecSysGrp().createSecSysGrp(auth, secGroupRead);
			secGroupReadID = secGroupRead.getRequiredSecSysGrpId();
		}

		if (secGroupReadIncSystemAdmin == null) {
			secGroupReadIncSystemAdmin = ICFSecSchema.getBackingCFSec().getCFSecFactory().getFactorySecSysGrpInc().newRec();
			secGroupReadIncSystemAdmin.setRequiredRevision(1);
			secGroupReadIncSystemAdmin.setCreatedAt(now);
			secGroupReadIncSystemAdmin.setCreatedByUserId(auth.getSecUserId());
			secGroupReadIncSystemAdmin.setUpdatedAt(now);
			secGroupReadIncSystemAdmin.setUpdatedByUserId(auth.getSecUserId());
			secGroupReadIncSystemAdmin.setRequiredContainerGroup(secGroupReadID);
			secGroupReadIncSystemAdmin.setRequiredParentSubGroup(systemGroup);
			secGroupReadIncSystemAdmin = ICFSecSchema.getBackingCFSec().getTableSecSysGrpInc().createSecSysGrpInc(auth, secGroupReadIncSystemAdmin);
		}

		if (secGroupRead != null && level == ICFSecPubSchema.SecLevelEnum.Global && secGroupReadIncPublic == null) {
			secGroupReadIncPublic = ICFSecSchema.getBackingCFSec().getCFSecFactory().getFactorySecSysGrpInc().newRec();
			secGroupReadIncPublic.setRequiredRevision(1);
			secGroupReadIncPublic.setCreatedAt(now);
			secGroupReadIncPublic.setCreatedByUserId(auth.getSecUserId());
			secGroupReadIncPublic.setUpdatedAt(now);
			secGroupReadIncPublic.setUpdatedByUserId(auth.getSecUserId());
			secGroupReadIncPublic.setRequiredContainerGroup(secGroupReadID);
			secGroupReadIncPublic.setRequiredParentSubGroup(publicGroup);
			secGroupReadIncPublic = ICFSecSchema.getBackingCFSec().getTableSecSysGrpInc().createSecSysGrpInc(auth, secGroupReadIncPublic);
		}
		else {
			secGroupReadIncPublic = null;
		}

		if (secGroupUpdate == null) {
			secGroupUpdate = ICFSecSchema.getBackingCFSec().getCFSecFactory().getFactorySecSysGrp().newRec();
			secGroupUpdate.setRequiredRevision(1);
			secGroupUpdate.setCreatedAt(now);
			secGroupUpdate.setCreatedByUserId(auth.getSecUserId());
			secGroupUpdate.setUpdatedAt(now);
			secGroupUpdate.setUpdatedByUserId(auth.getSecUserId());
			secGroupUpdate.setRequiredName(updatePermName);
			secGroupUpdate.setRequiredSecLevel(level);
			secGroupUpdate.setRequiredSecSysGrpId(secGroupUpdateID);
			secGroupUpdate = ICFSecSchema.getBackingCFSec().getTableSecSysGrp().createSecSysGrp(auth, secGroupUpdate);
			secGroupUpdateID = secGroupUpdate.getRequiredSecSysGrpId();
		}

		if (secGroupUpdateIncSystemAdmin == null) {
			secGroupUpdateIncSystemAdmin = ICFSecSchema.getBackingCFSec().getCFSecFactory().getFactorySecSysGrpInc().newRec();
			secGroupUpdateIncSystemAdmin.setRequiredRevision(1);
			secGroupUpdateIncSystemAdmin.setCreatedAt(now);
			secGroupUpdateIncSystemAdmin.setCreatedByUserId(auth.getSecUserId());
			secGroupUpdateIncSystemAdmin.setUpdatedAt(now);
			secGroupUpdateIncSystemAdmin.setUpdatedByUserId(auth.getSecUserId());
			secGroupUpdateIncSystemAdmin.setRequiredContainerGroup(secGroupUpdateID);
			secGroupUpdateIncSystemAdmin.setRequiredParentSubGroup(systemGroup);
			secGroupUpdateIncSystemAdmin = ICFSecSchema.getBackingCFSec().getTableSecSysGrpInc().createSecSysGrpInc(auth, secGroupUpdateIncSystemAdmin);
		}

		if (secGroupDelete == null) {
			secGroupDelete = ICFSecSchema.getBackingCFSec().getCFSecFactory().getFactorySecSysGrp().newRec();
			secGroupDelete.setRequiredRevision(1);
			secGroupDelete.setCreatedAt(now);
			secGroupDelete.setCreatedByUserId(auth.getSecUserId());
			secGroupDelete.setUpdatedAt(now);
			secGroupDelete.setUpdatedByUserId(auth.getSecUserId());
			secGroupDelete.setRequiredName(deletePermName);
			secGroupDelete.setRequiredSecLevel(level);
			secGroupDelete.setRequiredSecSysGrpId(secGroupDeleteID);
			secGroupDelete = ICFSecSchema.getBackingCFSec().getTableSecSysGrp().createSecSysGrp(auth, secGroupDelete);
			secGroupDeleteID = secGroupDelete.getRequiredSecSysGrpId();
		}

		if (secGroupDeleteIncSystemAdmin == null) {
			secGroupDeleteIncSystemAdmin = ICFSecSchema.getBackingCFSec().getCFSecFactory().getFactorySecSysGrpInc().newRec();
			secGroupDeleteIncSystemAdmin.setRequiredRevision(1);
			secGroupDeleteIncSystemAdmin.setCreatedAt(now);
			secGroupDeleteIncSystemAdmin.setCreatedByUserId(auth.getSecUserId());
			secGroupDeleteIncSystemAdmin.setUpdatedAt(now);
			secGroupDeleteIncSystemAdmin.setUpdatedByUserId(auth.getSecUserId());
			secGroupDeleteIncSystemAdmin.setRequiredContainerGroup(secGroupDeleteID);
			secGroupDeleteIncSystemAdmin.setRequiredParentSubGroup(systemGroup);
			secGroupDeleteIncSystemAdmin = ICFSecSchema.getBackingCFSec().getTableSecSysGrpInc().createSecSysGrpInc(auth, secGroupDeleteIncSystemAdmin);
		}
		
		if (hasHistory) {
			if (secGroupRestore == null) {
				secGroupRestore = ICFSecSchema.getBackingCFSec().getCFSecFactory().getFactorySecSysGrp().newRec();
				secGroupRestore.setRequiredRevision(1);
				secGroupRestore.setCreatedAt(now);
				secGroupRestore.setCreatedByUserId(auth.getSecUserId());
				secGroupRestore.setUpdatedAt(now);
				secGroupRestore.setUpdatedByUserId(auth.getSecUserId());
				secGroupRestore.setRequiredName(restorePermName);
				secGroupRestore.setRequiredSecLevel(level);
				secGroupRestore.setRequiredSecSysGrpId(secGroupRestoreID);
				secGroupRestore = ICFSecSchema.getBackingCFSec().getTableSecSysGrp().createSecSysGrp(auth, secGroupRestore);
				secGroupRestoreID = secGroupRestore.getRequiredSecSysGrpId();
			}

			if (secGroupRestoreIncSystemAdmin == null) {
				secGroupRestoreIncSystemAdmin = ICFSecSchema.getBackingCFSec().getCFSecFactory().getFactorySecSysGrpInc().newRec();
				secGroupRestoreIncSystemAdmin.setRequiredRevision(1);
				secGroupRestoreIncSystemAdmin.setCreatedAt(now);
				secGroupRestoreIncSystemAdmin.setCreatedByUserId(auth.getSecUserId());
				secGroupRestoreIncSystemAdmin.setUpdatedAt(now);
				secGroupRestoreIncSystemAdmin.setUpdatedByUserId(auth.getSecUserId());
				secGroupRestoreIncSystemAdmin.setRequiredContainerGroup(secGroupRestoreID);
				secGroupRestoreIncSystemAdmin.setRequiredParentSubGroup(systemGroup);
				secGroupRestoreIncSystemAdmin = ICFSecSchema.getBackingCFSec().getTableSecSysGrpInc().createSecSysGrpInc(auth, secGroupRestoreIncSystemAdmin);
			}
		}
		
		if (isMutable) {
			if (secGroupMutate == null) {
				secGroupMutate = ICFSecSchema.getBackingCFSec().getCFSecFactory().getFactorySecSysGrp().newRec();
				secGroupMutate.setRequiredRevision(1);
				secGroupMutate.setCreatedAt(now);
				secGroupMutate.setCreatedByUserId(auth.getSecUserId());
				secGroupMutate.setUpdatedAt(now);
				secGroupMutate.setUpdatedByUserId(auth.getSecUserId());
				secGroupMutate.setRequiredName(mutatePermName);
				secGroupMutate.setRequiredSecLevel(level);
				secGroupMutate.setRequiredSecSysGrpId(secGroupMutateID);
				secGroupMutate = ICFSecSchema.getBackingCFSec().getTableSecSysGrp().createSecSysGrp(auth, secGroupMutate);
				secGroupMutateID = secGroupMutate.getRequiredSecSysGrpId();
			}

			if (secGroupMutateIncSystemAdmin == null) {
				secGroupMutateIncSystemAdmin = ICFSecSchema.getBackingCFSec().getCFSecFactory().getFactorySecSysGrpInc().newRec();
				secGroupMutateIncSystemAdmin.setRequiredRevision(1);
				secGroupMutateIncSystemAdmin.setCreatedAt(now);
				secGroupMutateIncSystemAdmin.setCreatedByUserId(auth.getSecUserId());
				secGroupMutateIncSystemAdmin.setUpdatedAt(now);
				secGroupMutateIncSystemAdmin.setUpdatedByUserId(auth.getSecUserId());
				secGroupMutateIncSystemAdmin.setRequiredContainerGroup(secGroupMutateID);
				secGroupMutateIncSystemAdmin.setRequiredParentSubGroup(systemGroup);
				secGroupMutateIncSystemAdmin = ICFSecSchema.getBackingCFSec().getTableSecSysGrpInc().createSecSysGrpInc(auth, secGroupMutateIncSystemAdmin);
			}
		}
		
		if (level == ICFSecPubSchema.SecLevelEnum.Cluster || level == ICFSecPubSchema.SecLevelEnum.Tenant) {
			csecGroupCreate = ICFSecSchema.getBackingCFSec().getTableSecClusGrp().readDerivedByUNameIdx(auth, ICFSecSchema.getSysClusterId(), createPermName);
			if (csecGroupCreate != null) {
				csecGroupCreateID = csecGroupCreate.getRequiredSecClusGrpId();
			}
			else {
				csecGroupCreateID = null;
			}

			csecGroupRead = ICFSecSchema.getBackingCFSec().getTableSecClusGrp().readDerivedByUNameIdx(auth, ICFSecSchema.getSysClusterId(), readPermName);
			if (csecGroupRead != null) {
				csecGroupReadID = csecGroupRead.getRequiredSecClusGrpId();
			}
			else {
				csecGroupReadID = null;
			}

			csecGroupUpdate = ICFSecSchema.getBackingCFSec().getTableSecClusGrp().readDerivedByUNameIdx(auth, ICFSecSchema.getSysClusterId(), updatePermName);
			if (csecGroupUpdate != null) {
				csecGroupUpdateID = csecGroupUpdate.getRequiredSecClusGrpId();
			}
			else {
				csecGroupUpdateID = null;
			}

			csecGroupDelete = ICFSecSchema.getBackingCFSec().getTableSecClusGrp().readDerivedByUNameIdx(auth, ICFSecSchema.getSysClusterId(), deletePermName);
			if (csecGroupDelete != null) {
				csecGroupDeleteID = csecGroupDelete.getRequiredSecClusGrpId();
			}
			else {
				csecGroupDeleteID = null;
			}

			if (hasHistory) {
				csecGroupRestore = ICFSecSchema.getBackingCFSec().getTableSecClusGrp().readDerivedByUNameIdx(auth, ICFSecSchema.getSysClusterId(), restorePermName);
				if (csecGroupRestore != null) {
					csecGroupRestoreID = csecGroupRestore.getRequiredSecClusGrpId();
				}
				else {
					csecGroupRestoreID = null;
				}
			}
			else {
				csecGroupRestore = null;
				csecGroupRestoreID = null;
			}

			if (isMutable) {
				csecGroupMutate = ICFSecSchema.getBackingCFSec().getTableSecClusGrp().readDerivedByUNameIdx(auth, ICFSecSchema.getSysClusterId(), mutatePermName);
				if (csecGroupMutate != null) {
					csecGroupMutateID = csecGroupMutate.getRequiredSecClusGrpId();
				}
				else {
					csecGroupMutateID = null;
				}
			}
			else {
				csecGroupMutate = null;
				csecGroupMutateID = null;
			}

			if (csecGroupCreateID == null || csecGroupCreateID.isNull()) {
				csecGroupCreateID = new CFLibDbKeyHash256(0);
			}
			if (csecGroupReadID == null || csecGroupReadID.isNull()) {
				csecGroupReadID = new CFLibDbKeyHash256(0);
			}
			if (csecGroupUpdateID == null || csecGroupUpdateID.isNull()) {
				csecGroupUpdateID = new CFLibDbKeyHash256(0);
			}
			if (csecGroupDeleteID == null || csecGroupDeleteID.isNull()) {
				csecGroupDeleteID = new CFLibDbKeyHash256(0);
			}
			if (hasHistory) {
				if (csecGroupRestoreID == null || csecGroupRestoreID.isNull()) {
					csecGroupRestoreID = new CFLibDbKeyHash256(0);
				}
			}
			if (isMutable) {
				if (csecGroupMutateID == null || csecGroupMutateID.isNull()) {
					csecGroupMutateID = new CFLibDbKeyHash256(0);
				}
			}

			if (csecGroupCreate == null) {
				csecGroupCreate = ICFSecSchema.getBackingCFSec().getCFSecFactory().getFactorySecClusGrp().newRec();
				csecGroupCreate.setRequiredRevision(1);
				csecGroupCreate.setCreatedAt(now);
				csecGroupCreate.setCreatedByUserId(auth.getSecUserId());
				csecGroupCreate.setUpdatedAt(now);
				csecGroupCreate.setUpdatedByUserId(auth.getSecUserId());
				csecGroupCreate.setRequiredContainerSysGrp(createPermName);
				csecGroupCreate.setRequiredSecClusGrpId(csecGroupCreateID);
				csecGroupCreate.setRequiredOwnerCluster(secSysClusGroupSysAdmin.getRequiredOwnerCluster());
				csecGroupCreate = ICFSecSchema.getBackingCFSec().getTableSecClusGrp().createSecClusGrp(auth, csecGroupCreate);
				csecGroupCreateID = csecGroupCreate.getRequiredSecClusGrpId();
			}

			if (csecGroupRead == null) {
				csecGroupRead = ICFSecSchema.getBackingCFSec().getCFSecFactory().getFactorySecClusGrp().newRec();
				csecGroupRead.setRequiredRevision(1);
				csecGroupRead.setCreatedAt(now);
				csecGroupRead.setCreatedByUserId(auth.getSecUserId());
				csecGroupRead.setUpdatedAt(now);
				csecGroupRead.setUpdatedByUserId(auth.getSecUserId());
				csecGroupRead.setRequiredContainerSysGrp(readPermName);
				csecGroupRead.setRequiredSecClusGrpId(csecGroupReadID);
				csecGroupRead.setRequiredOwnerCluster(secSysClusGroupSysAdmin.getRequiredOwnerCluster());
				csecGroupRead = ICFSecSchema.getBackingCFSec().getTableSecClusGrp().createSecClusGrp(auth, csecGroupRead);
				csecGroupReadID = csecGroupRead.getRequiredSecClusGrpId();
			}

			if (csecGroupUpdate == null) {
				csecGroupUpdate = ICFSecSchema.getBackingCFSec().getCFSecFactory().getFactorySecClusGrp().newRec();
				csecGroupUpdate.setRequiredRevision(1);
				csecGroupUpdate.setCreatedAt(now);
				csecGroupUpdate.setCreatedByUserId(auth.getSecUserId());
				csecGroupUpdate.setUpdatedAt(now);
				csecGroupUpdate.setUpdatedByUserId(auth.getSecUserId());
				csecGroupUpdate.setRequiredContainerSysGrp(updatePermName);
				csecGroupUpdate.setRequiredSecClusGrpId(csecGroupUpdateID);
				csecGroupUpdate.setRequiredOwnerCluster(secSysClusGroupSysAdmin.getRequiredOwnerCluster());
				csecGroupUpdate = ICFSecSchema.getBackingCFSec().getTableSecClusGrp().createSecClusGrp(auth, csecGroupUpdate);
				csecGroupUpdateID = csecGroupUpdate.getRequiredSecClusGrpId();
			}

			if (csecGroupDelete == null) {
				csecGroupDelete = ICFSecSchema.getBackingCFSec().getCFSecFactory().getFactorySecClusGrp().newRec();
				csecGroupDelete.setRequiredRevision(1);
				csecGroupDelete.setCreatedAt(now);
				csecGroupDelete.setCreatedByUserId(auth.getSecUserId());
				csecGroupDelete.setUpdatedAt(now);
				csecGroupDelete.setUpdatedByUserId(auth.getSecUserId());
				csecGroupDelete.setRequiredContainerSysGrp(deletePermName);
				csecGroupDelete.setRequiredSecClusGrpId(csecGroupDeleteID);
				csecGroupDelete.setRequiredOwnerCluster(secSysClusGroupSysAdmin.getRequiredOwnerCluster());
				csecGroupDelete = ICFSecSchema.getBackingCFSec().getTableSecClusGrp().createSecClusGrp(auth, csecGroupDelete);
				csecGroupDeleteID = csecGroupDelete.getRequiredSecClusGrpId();
			}

			if (hasHistory) {
				if (csecGroupRestore == null) {
					csecGroupRestore = ICFSecSchema.getBackingCFSec().getCFSecFactory().getFactorySecClusGrp().newRec();
					csecGroupRestore.setRequiredRevision(1);
					csecGroupRestore.setCreatedAt(now);
					csecGroupRestore.setCreatedByUserId(auth.getSecUserId());
					csecGroupRestore.setUpdatedAt(now);
					csecGroupRestore.setUpdatedByUserId(auth.getSecUserId());
					csecGroupRestore.setRequiredContainerSysGrp(restorePermName);
					csecGroupRestore.setRequiredSecClusGrpId(csecGroupRestoreID);
					csecGroupRestore.setRequiredOwnerCluster(secSysClusGroupSysAdmin.getRequiredOwnerCluster());
					csecGroupRestore = ICFSecSchema.getBackingCFSec().getTableSecClusGrp().createSecClusGrp(auth, csecGroupRestore);
					csecGroupRestoreID = csecGroupRestore.getRequiredSecClusGrpId();
				}
			}

			if (isMutable) {
				if (csecGroupMutate == null) {
					csecGroupMutate = ICFSecSchema.getBackingCFSec().getCFSecFactory().getFactorySecClusGrp().newRec();
					csecGroupMutate.setRequiredRevision(1);
					csecGroupMutate.setCreatedAt(now);
					csecGroupMutate.setCreatedByUserId(auth.getSecUserId());
					csecGroupMutate.setUpdatedAt(now);
					csecGroupMutate.setUpdatedByUserId(auth.getSecUserId());
					csecGroupMutate.setRequiredContainerSysGrp(mutatePermName);
					csecGroupMutate.setRequiredSecClusGrpId(csecGroupMutateID);
					csecGroupMutate.setRequiredOwnerCluster(secSysClusGroupSysAdmin.getRequiredOwnerCluster());
					csecGroupMutate = ICFSecSchema.getBackingCFSec().getTableSecClusGrp().createSecClusGrp(auth, csecGroupMutate);
					csecGroupMutateID = csecGroupMutate.getRequiredSecClusGrpId();
				}
			}
		}

		if (level == ICFSecPubSchema.SecLevelEnum.Tenant ) {
			tsecGroupCreate = ICFSecSchema.getBackingCFSec().getTableSecTentGrp().readDerivedByUNameIdx(auth, ICFSecSchema.getSysTenantId(), createPermName);
			if (tsecGroupCreate != null) {
				tsecGroupCreateID = tsecGroupCreate.getRequiredSecTentGrpId();
			}
			else {
				tsecGroupCreateID = null;
			}

			tsecGroupRead = ICFSecSchema.getBackingCFSec().getTableSecTentGrp().readDerivedByUNameIdx(auth, ICFSecSchema.getSysTenantId(), readPermName);
			if (tsecGroupRead != null) {
				tsecGroupReadID = tsecGroupRead.getRequiredSecTentGrpId();
			}
			else {
				tsecGroupReadID = null;
			}

			tsecGroupUpdate = ICFSecSchema.getBackingCFSec().getTableSecTentGrp().readDerivedByUNameIdx(auth, ICFSecSchema.getSysTenantId(), updatePermName);
			if (tsecGroupUpdate != null) {
				tsecGroupUpdateID = tsecGroupUpdate.getRequiredSecTentGrpId();
			}
			else {
				tsecGroupUpdateID = null;
			}

			tsecGroupDelete = ICFSecSchema.getBackingCFSec().getTableSecTentGrp().readDerivedByUNameIdx(auth, ICFSecSchema.getSysTenantId(), deletePermName);
			if (tsecGroupDelete != null) {
				tsecGroupDeleteID = tsecGroupDelete.getRequiredSecTentGrpId();
			}
			else {
				tsecGroupDeleteID = null;
			}

			if (hasHistory) {
				tsecGroupRestore = ICFSecSchema.getBackingCFSec().getTableSecTentGrp().readDerivedByUNameIdx(auth, ICFSecSchema.getSysTenantId(), restorePermName);
				if (tsecGroupRestore != null) {
					tsecGroupRestoreID = tsecGroupRestore.getRequiredSecTentGrpId();
				}
				else {
					tsecGroupRestoreID = null;
				}
			}
			else {
				tsecGroupRestore = null;
				tsecGroupRestoreID = null;
			}

			if (isMutable) {
				tsecGroupMutate = ICFSecSchema.getBackingCFSec().getTableSecTentGrp().readDerivedByUNameIdx(auth, ICFSecSchema.getSysTenantId(), mutatePermName);
				if (tsecGroupMutate != null) {
					tsecGroupMutateID = tsecGroupMutate.getRequiredSecTentGrpId();
				}
				else {
					tsecGroupMutateID = null;
				}
			}
			else {
				tsecGroupMutate = null;
				tsecGroupMutateID = null;
			}

			if (tsecGroupCreateID == null || tsecGroupCreateID.isNull()) {
				tsecGroupCreateID = new CFLibDbKeyHash256(0);
			}
			if (tsecGroupReadID == null || tsecGroupReadID.isNull()) {
				tsecGroupReadID = new CFLibDbKeyHash256(0);
			}
			if (tsecGroupUpdateID == null || tsecGroupUpdateID.isNull()) {
				tsecGroupUpdateID = new CFLibDbKeyHash256(0);
			}
			if (tsecGroupDeleteID == null || tsecGroupDeleteID.isNull()) {
				tsecGroupDeleteID = new CFLibDbKeyHash256(0);
			}
			if (hasHistory) {
				if (tsecGroupRestoreID == null || tsecGroupRestoreID.isNull()) {
					tsecGroupRestoreID = new CFLibDbKeyHash256(0);
				}
			}
			if (isMutable) {
				if (tsecGroupMutateID == null || tsecGroupMutateID.isNull()) {
					tsecGroupMutateID = new CFLibDbKeyHash256(0);
				}
			}

			if (tsecGroupCreate == null) {
				tsecGroupCreate = ICFSecSchema.getBackingCFSec().getCFSecFactory().getFactorySecTentGrp().newRec();
				tsecGroupCreate.setRequiredRevision(1);
				tsecGroupCreate.setCreatedAt(now);
				tsecGroupCreate.setCreatedByUserId(auth.getSecUserId());
				tsecGroupCreate.setUpdatedAt(now);
				tsecGroupCreate.setUpdatedByUserId(auth.getSecUserId());
				tsecGroupCreate.setRequiredContainerSysGrp(createPermName);
				tsecGroupCreate.setRequiredSecTentGrpId(tsecGroupCreateID);
				tsecGroupCreate.setRequiredOwnerTenant(secSysTentGroupSysAdmin.getRequiredOwnerTenant());
				tsecGroupCreate = ICFSecSchema.getBackingCFSec().getTableSecTentGrp().createSecTentGrp(auth, tsecGroupCreate);
				tsecGroupCreateID = tsecGroupCreate.getRequiredSecTentGrpId();
			}

			if (tsecGroupRead == null) {
				tsecGroupRead = ICFSecSchema.getBackingCFSec().getCFSecFactory().getFactorySecTentGrp().newRec();
				tsecGroupRead.setRequiredRevision(1);
				tsecGroupRead.setCreatedAt(now);
				tsecGroupRead.setCreatedByUserId(auth.getSecUserId());
				tsecGroupRead.setUpdatedAt(now);
				tsecGroupRead.setUpdatedByUserId(auth.getSecUserId());
				tsecGroupRead.setRequiredContainerSysGrp(readPermName);
				tsecGroupRead.setRequiredSecTentGrpId(tsecGroupReadID);
				tsecGroupRead.setRequiredOwnerTenant(secSysTentGroupSysAdmin.getRequiredOwnerTenant());
				tsecGroupRead = ICFSecSchema.getBackingCFSec().getTableSecTentGrp().createSecTentGrp(auth, tsecGroupRead);
				tsecGroupReadID = tsecGroupRead.getRequiredSecTentGrpId();
			}

			if (tsecGroupUpdate == null) {
				tsecGroupUpdate = ICFSecSchema.getBackingCFSec().getCFSecFactory().getFactorySecTentGrp().newRec();
				tsecGroupUpdate.setRequiredRevision(1);
				tsecGroupUpdate.setCreatedAt(now);
				tsecGroupUpdate.setCreatedByUserId(auth.getSecUserId());
				tsecGroupUpdate.setUpdatedAt(now);
				tsecGroupUpdate.setUpdatedByUserId(auth.getSecUserId());
				tsecGroupUpdate.setRequiredContainerSysGrp(updatePermName);
				tsecGroupUpdate.setRequiredSecTentGrpId(tsecGroupUpdateID);
				tsecGroupUpdate.setRequiredOwnerTenant(secSysTentGroupSysAdmin.getRequiredOwnerTenant());
				tsecGroupUpdate = ICFSecSchema.getBackingCFSec().getTableSecTentGrp().createSecTentGrp(auth, tsecGroupUpdate);
				tsecGroupUpdateID = tsecGroupUpdate.getRequiredSecTentGrpId();
			}

			if (tsecGroupDelete == null) {
				tsecGroupDelete = ICFSecSchema.getBackingCFSec().getCFSecFactory().getFactorySecTentGrp().newRec();
				tsecGroupDelete.setRequiredRevision(1);
				tsecGroupDelete.setCreatedAt(now);
				tsecGroupDelete.setCreatedByUserId(auth.getSecUserId());
				tsecGroupDelete.setUpdatedAt(now);
				tsecGroupDelete.setUpdatedByUserId(auth.getSecUserId());
				tsecGroupDelete.setRequiredContainerSysGrp(deletePermName);
				tsecGroupDelete.setRequiredSecTentGrpId(tsecGroupDeleteID);
				tsecGroupDelete.setRequiredOwnerTenant(secSysTentGroupSysAdmin.getRequiredOwnerTenant());
				tsecGroupDelete = ICFSecSchema.getBackingCFSec().getTableSecTentGrp().createSecTentGrp(auth, tsecGroupDelete);
				tsecGroupDeleteID = tsecGroupDelete.getRequiredSecTentGrpId();
			}

			if (hasHistory) {
				if (tsecGroupRestore == null) {
					tsecGroupRestore = ICFSecSchema.getBackingCFSec().getCFSecFactory().getFactorySecTentGrp().newRec();
					tsecGroupRestore.setRequiredRevision(1);
					tsecGroupRestore.setCreatedAt(now);
					tsecGroupRestore.setCreatedByUserId(auth.getSecUserId());
					tsecGroupRestore.setUpdatedAt(now);
					tsecGroupRestore.setUpdatedByUserId(auth.getSecUserId());
					tsecGroupRestore.setRequiredContainerSysGrp(restorePermName);
					tsecGroupRestore.setRequiredSecTentGrpId(tsecGroupRestoreID);
					tsecGroupRestore.setRequiredOwnerTenant(secSysTentGroupSysAdmin.getRequiredOwnerTenant());
					tsecGroupRestore = ICFSecSchema.getBackingCFSec().getTableSecTentGrp().createSecTentGrp(auth, tsecGroupRestore);
					tsecGroupRestoreID = tsecGroupRestore.getRequiredSecTentGrpId();
				}
			}

			if (isMutable) {
				if (tsecGroupMutate == null) {
					tsecGroupMutate = ICFSecSchema.getBackingCFSec().getCFSecFactory().getFactorySecTentGrp().newRec();
					tsecGroupMutate.setRequiredRevision(1);
					tsecGroupMutate.setCreatedAt(now);
					tsecGroupMutate.setCreatedByUserId(auth.getSecUserId());
					tsecGroupMutate.setUpdatedAt(now);
					tsecGroupMutate.setUpdatedByUserId(auth.getSecUserId());
					tsecGroupMutate.setRequiredContainerSysGrp(mutatePermName);
					tsecGroupMutate.setRequiredSecTentGrpId(tsecGroupMutateID);
					tsecGroupMutate.setRequiredOwnerTenant(secSysTentGroupSysAdmin.getRequiredOwnerTenant());
					tsecGroupMutate = ICFSecSchema.getBackingCFSec().getTableSecTentGrp().createSecTentGrp(auth, tsecGroupMutate);
					tsecGroupMutateID = tsecGroupMutate.getRequiredSecTentGrpId();
				}
			}
		}
	}		

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void bootstrapAllTablesSecurity(CFSecPubTableData tableData[]) {
		bootstrapAllTablesSecurity(ICFSecSchema.getSysClusterId(), ICFSecSchema.getSysTenantId(), tableData);
	}

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void bootstrapAllTablesSecurity(CFLibDbKeyHash256 clusterId, CFLibDbKeyHash256 tenantId, CFSecPubTableData tableData[]) {
		LocalDateTime now = LocalDateTime.now();
		ICFSecSecSession bootstrapSession;
		CFLibDbKeyHash256 bootstrapSessionID = new CFLibDbKeyHash256(0);
		CFLibDbKeyHash256 systemUID = ICFSecSchema.getSystemId();

		CFSecAuthorization auth = new CFSecAuthorization();
		auth.setSecUserId(systemUID);
		auth.setAuthUuid6(CFLibUuid6.generateUuid6());
		auth.setSecClusterId(clusterId);
		auth.setSecTenantId(tenantId);
		auth.setSecSessionId(bootstrapSessionID);
		ICFSecSchema.setAuthorizationCallback( new ICFSecAuthorizationCallback() {
			CFSecAuthorization myauth = auth;
			@Override
			public ICFSecAuthorization getEffectiveAuthorization() {
				return(myauth);
			}
		});

//ICFSecSchema.getSysTenantId(), ICFSecSchema.getSystemId()
		bootstrapSession = ICFSecSchema.getBackingCFSec().getCFSecFactory().getFactorySecSession().newRec();
		bootstrapSession.setRequiredRevision(1);
		bootstrapSession.setRequiredSecSessionId(bootstrapSessionID);
		bootstrapSession.setRequiredSecUserId(systemUID);
		bootstrapSession.setOptionalSecProxyId(systemUID);
		bootstrapSession.setRequiredStart(now);
		bootstrapSession.setOptionalFinish(null);
		bootstrapSession = ICFSecSchema.getBackingCFSec().getTableSecSession().createSecSession(auth, bootstrapSession);
		bootstrapSessionID = bootstrapSession.getRequiredSecSessionId();

		ICFSecSecSysGrp secSystemAdminGroup = ICFSecSchema.getBackingCFSec().getTableSecSysGrp().readDerivedByUNameIdx( auth, "systemadmin");
		if (secSystemAdminGroup == null) {
			throw new CFLibNullArgumentException(getClass(), "bootstrapAllTablesSecurity", 0, "secSystemAdminGroup");
		}

		ICFSecSecSysGrp secSysGroupPublic = ICFSecSchema.getBackingCFSec().getTableSecSysGrp().readDerivedByUNameIdx( auth, "public");
		if (secSysGroupPublic == null) {
			throw new CFLibNullArgumentException(getClass(), "bootstrapAllTablesSecurity", 0, "secSysGroupPublic");
		}
		
		ICFSecCluster secCluster = ICFSecSchema.getBackingCFSec().getTableCluster().readDerived(auth, clusterId);
		if (secCluster == null) {
			throw new CFLibNullArgumentException(getClass(), "bootstrapAllTablesSecurity", 0, "secCluster<" + clusterId.toString() + ">");
		}
		
		ICFSecTenant secTenant = ICFSecSchema.getBackingCFSec().getTableTenant().readDerived(auth, tenantId);
		if (secTenant == null) {
			throw new CFLibNullArgumentException(getClass(), "bootstrapAllTablesSecurity", 0, "secTenant<" + tenantId.toString() + ">");
		}
	
		bootstrapAllTablesSecurity(auth, systemUID, bootstrapSession, secSystemAdminGroup, secSysGroupPublic, secCluster, secTenant, tableData);

		if (bootstrapSession != null && bootstrapSessionID != null && !bootstrapSessionID.isNull() && bootstrapSession.getOptionalFinish() == null) {
			bootstrapSession.setOptionalFinish(LocalDateTime.now());
			bootstrapSession = ICFSecSchema.getBackingCFSec().getTableSecSession().updateSecSession(auth, bootstrapSession);
			ICFSecSchema.setAuthorizationCallback( new ICFSecAuthorizationCallback() {
				@Override
				public ICFSecAuthorization getEffectiveAuthorization() {
					return(null);
				}
			});
		}
	}

	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void bootstrapAllTablesSecurity(ICFSecAuthorization auth,
		CFLibDbKeyHash256 systemUID,
		ICFSecSecSession bootstrapSession,
		ICFSecSecSysGrp secSystemAdminGroup,
		ICFSecSecSysGrp secSysGroupPublic,
		ICFSecCluster secCluster,
		ICFSecTenant secTenant,
		CFSecPubTableData tableData[])
	{
		LocalDateTime now = LocalDateTime.now();

		CFLibDbKeyHash256 bootstrapSessionID = bootstrapSession.getRequiredSecSessionId();
		if (secSystemAdminGroup == null) {
			throw new CFLibNullArgumentException(getClass(), "bootstrapAllTablesSecurity", 0, "secSystemAdminGroup");
		}
		if (secSysGroupPublic == null) {
			throw new CFLibNullArgumentException(getClass(), "bootstrapAllTablesSecurity", 0, "secSysGroupPublic");
		}
		if (secCluster == null) {
			throw new CFLibNullArgumentException(getClass(), "bootstrapAllTablesSecurity", 0, "secCluster");
		}
		if (secTenant == null) {
			throw new CFLibNullArgumentException(getClass(), "bootstrapAllTablesSecurity", 0, "secTenant");
		}

		ICFSecSecSysGrp secSysClusGroupSysAdmin = ICFSecSchema.getBackingCFSec().getTableSecSysGrp().readDerivedByUNameIdx(auth, secCluster.getRequiredDescription().toLowerCase() + "clusteradmin");
		if (secSysClusGroupSysAdmin == null) {
			secSysClusGroupSysAdmin = ICFSecSchema.getBackingCFSec().getCFSecFactory().getFactorySecSysGrp().newRec();
			secSysClusGroupSysAdmin.setCreatedAt(now);
			secSysClusGroupSysAdmin.setCreatedByUserId(systemUID);
			secSysClusGroupSysAdmin.setUpdatedAt(now);
			secSysClusGroupSysAdmin.setUpdatedByUserId(systemUID);
			secSysClusGroupSysAdmin.setRequiredName(secCluster.getRequiredDescription().toLowerCase() + "clusteradmin");
			secSysClusGroupSysAdmin.setRequiredRevision(1);
			secSysClusGroupSysAdmin = ICFSecSchema.getBackingCFSec().getTableSecSysGrp().createSecSysGrp(auth, secSysClusGroupSysAdmin);
		}

		ICFSecSecSysGrp secSysTentGroupSysAdmin = ICFSecSchema.getBackingCFSec().getTableSecSysGrp().readDerivedByUNameIdx(auth, secTenant.getRequiredTenantName().toLowerCase() + "tenantadmin");
		if (secSysTentGroupSysAdmin == null) {
			secSysTentGroupSysAdmin = ICFSecSchema.getBackingCFSec().getCFSecFactory().getFactorySecSysGrp().newRec();
			secSysTentGroupSysAdmin.setCreatedAt(now);
			secSysTentGroupSysAdmin.setCreatedByUserId(systemUID);
			secSysTentGroupSysAdmin.setUpdatedAt(now);
			secSysTentGroupSysAdmin.setUpdatedByUserId(systemUID);
			secSysTentGroupSysAdmin.setRequiredName(secTenant.getRequiredTenantName().toLowerCase() + "tenantadmin");
			secSysTentGroupSysAdmin.setRequiredRevision(1);
			secSysTentGroupSysAdmin = ICFSecSchema.getBackingCFSec().getTableSecSysGrp().createSecSysGrp(auth, secSysTentGroupSysAdmin);
		}

		ICFSecSecClusGrp secClusGroupSysAdmin = ICFSecSchema.getBackingCFSec().getTableSecClusGrp().readDerivedByUNameIdx(auth, secCluster.getRequiredId(), secCluster.getRequiredDescription().toLowerCase() + "clusteradmin");
		if (secClusGroupSysAdmin == null) {
			secClusGroupSysAdmin = ICFSecSchema.getBackingCFSec().getCFSecFactory().getFactorySecClusGrp().newRec();
			secClusGroupSysAdmin.setCreatedAt(now);
			secClusGroupSysAdmin.setCreatedByUserId(systemUID);
			secClusGroupSysAdmin.setUpdatedAt(now);
			secClusGroupSysAdmin.setUpdatedByUserId(systemUID);
			secClusGroupSysAdmin.setRequiredContainerSysGrp(secCluster.getRequiredDescription().toLowerCase() + "clusteradmin");
			secClusGroupSysAdmin.setRequiredOwnerCluster(secCluster);
			secClusGroupSysAdmin.setRequiredRevision(1);
			secClusGroupSysAdmin = ICFSecSchema.getBackingCFSec().getTableSecClusGrp().createSecClusGrp(auth, secClusGroupSysAdmin);
		}

		ICFSecSecClusGrpMemb secClusGroupMembSystemAdmin = ICFSecSchema.getBackingCFSec().getTableSecClusGrpMemb().readDerivedByIdIdx(auth, secClusGroupSysAdmin.getRequiredSecClusGrpId(), "systemadmin");
		if (secClusGroupMembSystemAdmin == null) {
			secClusGroupMembSystemAdmin = new CFSecJpaSecClusGrpMemb();
			secClusGroupMembSystemAdmin.setRequiredContainerGroup(secClusGroupSysAdmin);
			secClusGroupMembSystemAdmin.setCreatedAt(now);
			secClusGroupMembSystemAdmin.setCreatedByUserId(systemUID);
			secClusGroupMembSystemAdmin.setUpdatedAt(now);
			secClusGroupMembSystemAdmin.setUpdatedByUserId(systemUID);
			secClusGroupMembSystemAdmin.setRequiredParentUser("systemadmin");
			secClusGroupMembSystemAdmin.setRequiredRevision(1);
			secClusGroupMembSystemAdmin = (CFSecJpaSecClusGrpMemb)(secclusgrpmembService.create((CFSecJpaSecClusGrpMemb)secClusGroupMembSystemAdmin));
		}
		
		ICFSecSecTentGrp secTentGroupSysAdmin = ICFSecSchema.getBackingCFSec().getTableSecTentGrp().readDerivedByUNameIdx(auth, secTenant.getRequiredId(), secTenant.getRequiredTenantName().toLowerCase() + "tenantadmin");
		if (secTentGroupSysAdmin == null) {
			secTentGroupSysAdmin = ICFSecSchema.getBackingCFSec().getCFSecFactory().getFactorySecTentGrp().newRec();
			secTentGroupSysAdmin.setCreatedAt(now);
			secTentGroupSysAdmin.setCreatedByUserId(systemUID);
			secTentGroupSysAdmin.setUpdatedAt(now);
			secTentGroupSysAdmin.setUpdatedByUserId(systemUID);
			secTentGroupSysAdmin.setRequiredContainerSysGrp(secTenant.getRequiredTenantName().toLowerCase() + "tenantadmin");
			secTentGroupSysAdmin.setRequiredOwnerTenant(secTenant);
			secTentGroupSysAdmin.setRequiredRevision(1);
			secTentGroupSysAdmin = ICFSecSchema.getBackingCFSec().getTableSecTentGrp().createSecTentGrp(auth, secTentGroupSysAdmin);
		}

		ICFSecSecTentGrpMemb secTentGroupMembSystemAdmin = ICFSecSchema.getBackingCFSec().getTableSecTentGrpMemb().readDerivedByIdIdx(auth, secTentGroupSysAdmin.getRequiredSecTentGrpId(), "systemadmin");
		if (secTentGroupMembSystemAdmin == null) {
			secTentGroupMembSystemAdmin = new CFSecJpaSecTentGrpMemb();
			secTentGroupMembSystemAdmin.setRequiredContainerGroup(secTentGroupSysAdmin);
			secTentGroupMembSystemAdmin.setCreatedAt(now);
			secTentGroupMembSystemAdmin.setCreatedByUserId(systemUID);
			secTentGroupMembSystemAdmin.setUpdatedAt(now);
			secTentGroupMembSystemAdmin.setUpdatedByUserId(systemUID);
			secTentGroupMembSystemAdmin.setRequiredParentUser("systemadmin");
			secTentGroupMembSystemAdmin.setRequiredRevision(1);
			secTentGroupMembSystemAdmin = (CFSecJpaSecTentGrpMemb)(sectentgrpmembService.create((CFSecJpaSecTentGrpMemb)secTentGroupMembSystemAdmin));
		}

		for( CFSecPubTableData data: tableData) {
			bootstrapTableSecurity(auth, LocalDateTime.now(), data.getTableName(), data.hasHistory(), data.isMutable(), data.getScope(), secSysGroupPublic, secSystemAdminGroup, secClusGroupSysAdmin, secTentGroupSysAdmin);
		}
	}


	/***** Internal low-level security service methods to satisfy SecurityCache implementations */

	/**
	 *	Count system-level security access for permission granted to a specific user by LoginId.
	 *
	 *		@param parmPermName The name of the permission to be checked (all lowercase in the case of generated permission names; custom roles might be mixed-case)
	 *		@param parmLoginId The LoginId of the user being authorized.
	 *		@return The number of authorizations for the specified permission and user, with an 8-level deep union in play.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	long countSysSecurityPermsByLoginId(String parmPermName, String parmLoginId) {
		EntityManager em = cfsec31EntityManagerFactory.getNativeEntityManagerFactory().createEntityManager();
		TypedQuery<Long> query = em.createNamedQuery("cFSec31SecUser.countSysSecurityPermsByLoginId", Long.class);
		query.setParameter("parmPermName", parmPermName);
		query.setParameter("parmLoginId", parmLoginId);
		Long val = query.getSingleResult();
		em.close();
		if (val != null) {
			return(val);
		}
		else {
			return(0L);
		}
	}

	/**
	 *	Count system-level security access for permission granted to a specific user by SecUserId.
	 *
	 *		@param parmPermName The name of the permission to be checked (all lowercase in the case of generated permission names; custom roles might be mixed-case)
	 *		@param parmUserId The UserId of the user being authorized.
	 *		@return The number of authorizations for the specified permission and user, with an 8-level deep union in play.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	long countSysSecurityPermsByUserId(String parmPermName, CFLibDbKeyHash256 parmUserId) {
		EntityManager em = cfsec31EntityManagerFactory.getNativeEntityManagerFactory().createEntityManager();
		TypedQuery<Long> query = em.createNamedQuery("cFSec31SecUser.countSysSecurityPermsByUserId", Long.class);
		query.setParameter("parmPermName", parmPermName);
		query.setParameter("parmUserId", parmUserId);
		Long val = query.getSingleResult();
		em.close();
		if (val != null) {
			return(val);
		}
		else {
			return(0L);
		}
	}

	/**
	 *	Count cluster-level security access for permission granted to a specific user by LoginId for the specified ClusterId.
	 *
	 *		@param parmPermName The name of the permission to be checked (all lowercase in the case of generated permission names; custom roles might be mixed-case)
	 *		@param parmLoginId The LoginId of the user being authorized.
	 *		@param parmClusterId The ClusterId of the permission to be checked (not necessarily the user's current cluster)
	 *		@return The number of authorizations for the specified permission and user, with an 8-level deep union in play.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	long countClusSecurityPermsByLoginId(String parmPermName, String parmLoginId, CFLibDbKeyHash256 parmClusterId) {
		EntityManager em = cfsec31EntityManagerFactory.getNativeEntityManagerFactory().createEntityManager();
		TypedQuery<Long> query = em.createNamedQuery("cFSec31SecUser.countClusSecurityPermsByLoginId", Long.class);
		query.setParameter("parmPermName", parmPermName);
		query.setParameter("parmLoginId", parmLoginId);
		query.setParameter("parmClusterId", parmClusterId);
		Long val = query.getSingleResult();
		em.close();
		if (val != null) {
			return(val);
		}
		else {
			return(0L);
		}
	}

	/**
	 *	Count cluster-level security access for permission granted to a specific user by SecUserId for the specified ClusterId.
	 *
	 *		@param parmPermName The name of the permission to be checked (all lowercase in the case of generated permission names; custom roles might be mixed-case)
	 *		@param parmLoginId The LoginId of the user being authorized.
	 *		@param parmClusterId The ClusterId of the permission to be checked (not necessarily the user's current cluster)
	 *		@return The number of authorizations for the specified permission and user, with an 8-level deep union in play.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	long countClusSecurityPermsByUserId(String parmPermName, CFLibDbKeyHash256 parmUserId, CFLibDbKeyHash256 parmClusterId) {
		EntityManager em = cfsec31EntityManagerFactory.getNativeEntityManagerFactory().createEntityManager();
		TypedQuery<Long> query = em.createNamedQuery("cFSec31SecUser.countClusSecurityPermsByUserId", Long.class);
		query.setParameter("parmPermName", parmPermName);
		query.setParameter("parmUserId", parmUserId);
		query.setParameter("parmClusterId", parmClusterId);
		Long val = query.getSingleResult();
		em.close();
		if (val != null) {
			return(val);
		}
		else {
			return(0L);
		}
	}

	/**
	 *	Count tenant-level security access for permission granted to a specific user by LoginId for the specified TenantId.
	 *
	 *		@param parmPermName The name of the permission to be checked (all lowercase in the case of generated permission names; custom roles might be mixed-case)
	 *		@param parmLoginId The LoginId of the user being authorized.
	 *		@param parmTenantId The TenantId of the permission to be checked (not necessarily the user's current tenant)
	 *		@return The number of authorizations for the specified permission and user, with an 8-level deep union in play.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	long countTentSecurityPermsByLoginId(String parmPermName, String parmLoginId, CFLibDbKeyHash256 parmTenantId) {
		EntityManager em = cfsec31EntityManagerFactory.getNativeEntityManagerFactory().createEntityManager();
		TypedQuery<Long> query = em.createNamedQuery("cFSec31SecUser.countTentSecurityPermsByLoginId", Long.class);
		query.setParameter("parmPermName", parmPermName);
		query.setParameter("parmLoginId", parmLoginId);
		query.setParameter("parmTenantId", parmTenantId);
		Long val = query.getSingleResult();
		em.close();
		if (val != null) {
			return(val);
		}
		else {
			return(0L);
		}
	}

	/**
	 *	Count tenant-level security access for permission granted to a specific user by SecUserId for the specified TenantId.
	 *
	 *		@param parmPermName The name of the permission to be checked (all lowercase in the case of generated permission names; custom roles might be mixed-case)
	 *		@param parmLoginId The LoginId of the user being authorized.
	 *		@param parmTenantId The TenantId of the permission to be checked (not necessarily the user's current tenant)
	 *		@return The number of authorizations for the specified permission and user, with an 8-level deep union in play.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	long countTentSecurityPermsByUserId(String parmPermName, CFLibDbKeyHash256 parmUserId, CFLibDbKeyHash256 parmTenantId) {
		EntityManager em = cfsec31EntityManagerFactory.getNativeEntityManagerFactory().createEntityManager();
		TypedQuery<Long> query = em.createNamedQuery("cFSec31SecUser.countTentSecurityPermsByUserId", Long.class);
		query.setParameter("parmPermName", parmPermName);
		query.setParameter("parmUserId", parmUserId);
		query.setParameter("parmTenantId", parmTenantId);
		Long val = query.getSingleResult();
		em.close();
		if (val != null) {
			return(val);
		}
		else {
			return(0L);
		}
	}

	/***** Backend security service methods */

	/**
	 *	Map the userLogin string to a userId DbKey.
	 *
	 *	@param userLogin 
	 *	@return null if the userLogin does not exist, is null, is empty, or is blank. Otherwise the DbKey for the user.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFLibDbKeyHash256 mapUserLoginToUserId(String userLogin) {
		final String S_ProcName = "mapUserLoginToUserId";
		if (userLogin == null || userLogin.isEmpty() || userLogin.isBlank()) {
			return(null);
		}
		CFSecJpaSecUser rec = secuserService.findByULoginIdx(userLogin);
		if (rec == null) {
			return(null);
		}
		else {
			return(rec.getPKey());
		}
	}

	/**
	 *	Map the userId DbKey to the userLogin string.
	 *
	 *	@param userId
	 *	@return null if the userId does not exist or is null. Otherwise the userLogin for the user.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public String mapUserIdToUserLogin(CFLibDbKeyHash256 userId) {
		final String S_ProcName = "mapUserIdToUserLogin";
		if (userId == null || userId.isNull()) {
			return(null);
		}
		CFSecJpaSecUser rec = secuserService.find(userId);
		if (rec == null) {
			return(null);
		}
		else {
			return(rec.getRequiredLoginId());
		}
	}

	/**
	 *	Probe the back-end SecRole*, SecTent* security tables, then the SecClus* security tables, and finally the SecSys* tables
	 *	in order until a probe authorizes the users access to the permission role or group.  The probed value is then "acquired" by
	 *	the cache and kept until it expires or is forgotten by the cache.
	 *
	 *	@param userId The user id for the SecUser object this query is for.
	 *	@param clusterId The cluster id of the cluster that contains the tenant being queried.
	 *	@param tenantId The tenant id being queried.
	 *	@param permissionName The name of the permission role or group being queried.
	 *
	 *	@return true if the user is a member of the tenant role or group, the equivalent cluster admin role or group, or the equivalent system admin role or group, otherwise false.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public boolean probeMemberOfTenantGroup(CFLibDbKeyHash256 userId, CFLibDbKeyHash256 clusterId, CFLibDbKeyHash256 tenantId, String permissionName) {
		if (userId == null || userId.isNull()) {
			return(false);
		}
		if (permissionName == null || permissionName.isEmpty() || permissionName.isBlank()) {
			return(false);
		}
		if (clusterId == null || clusterId.isNull()) {
			return(false);
		}
		if (tenantId == null || tenantId.isNull()) {
			return(false);
		}
		long granted = countTentSecurityPermsByUserId(permissionName, userId, tenantId);
		if (granted > 0) {
			return(true);
		}
		granted = countClusSecurityPermsByUserId(permissionName, userId, clusterId);
		if (granted > 0) {
			return(true);
		}
		granted = countSysSecurityPermsByUserId(permissionName, userId);
		if (granted > 0) {
			return(true);
		}
		return(false);
	}

	/**
	 *	Probe the back-end SecRole*, SecClus* security tables, and finally the SecSys* tables in order until a probe authorizes
	 *	the users access to the permission role or group.  The probed value is then "acquired" by the cache and kept until it
	 *	expires or is forgotten by the cache.
	 *
	 *	@param userId The user id for the SecUser object this query is for.
	 *	@param clusterId The cluster id of the cluster that contains the tenant being queried.
	 *	@param permissionName The name of the permission role or group being queried.
	 *
	 *	@return true if the user is a member of the tenant role or group, the equivalent cluster admin role or group, or the equivalent system admin role or group, otherwise false.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public boolean probeMemberOfClusterGroup(CFLibDbKeyHash256 userId, CFLibDbKeyHash256 clusterId, String permissionName) {
		if (userId == null || userId.isNull()) {
			return(false);
		}
		if (permissionName == null || permissionName.isEmpty() || permissionName.isBlank()) {
			return(false);
		}
		if (clusterId == null || clusterId.isNull()) {
			return(false);
		}
		long granted = countClusSecurityPermsByUserId(permissionName, userId, clusterId);
		if (granted > 0) {
			return(true);
		}
		granted = countSysSecurityPermsByUserId(permissionName, userId);
		if (granted > 0) {
			return(true);
		}
		return(false);
	}

	/**
	 *	Probe the back-end SecRole*, and SecSys* tables until a probe authorizes the users access to the permission role or group.
	 *	The probed value is then "acquired" by the cache and kept until it expires or is forgotten by the cache.
	 *
	 *	@param userId The user id for the SecUser object this query is for.
	 *	@param permissionName The name of the permission role or group being queried.
	 *
	 *	@return true if the user is a member of the tenant role or group, the equivalent cluster admin role or group, or the equivalent system admin role or group, otherwise false.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public boolean probeMemberOfSystemGroup(CFLibDbKeyHash256 userId, String permissionName) {
		if (userId == null || userId.isNull()) {
			return(false);
		}
		if (permissionName == null || permissionName.isEmpty() || permissionName.isBlank()) {
			return(false);
		}
		long granted = countSysSecurityPermsByUserId(permissionName, userId);
		if (granted > 0) {
			return(true);
		}
		return(false);
	}

		// Customized schematweak [CFSec::CFSec].JpaSchemaServiceCustomServices
}
