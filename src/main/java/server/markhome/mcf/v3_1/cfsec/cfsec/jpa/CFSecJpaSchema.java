// Description: Java 25 JPA implementation of a CFSec schema.

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
//package server.markhome.mcf.v3_1.cfsec.cfsec.jpa;

import java.io.Serializable;
import java.math.*;
import java.time.*;
import java.net.InetAddress;
import java.util.*;
import jakarta.persistence.*;
import jakarta.transaction.Transactional;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.text.StringEscapeUtils;
import org.springframework.beans.factory.annotation.Autowired;
import java.util.concurrent.atomic.*;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import server.markhome.mcf.v3_1.cflib.*;
import server.markhome.mcf.v3_1.cflib.dbutil.*;
import server.markhome.mcf.v3_1.cflib.inz.Inz;
import server.markhome.mcf.v3_1.cflib.xml.CFLibXmlUtil;
import server.markhome.mcf.v3_1.cfsec.cfsec.*;
import server.markhome.mcf.v3_1.cfsec.cfsec.jpa.CFSecJpaHooksSchema;

public class CFSecJpaSchema
	implements ICFSecSchema
{
	private CFSecJpaHooksSchema cfsecJpaHooksSchema = null;

	protected static ICFSecTablePerms tablePerms;
	protected ICFSecClusterTable tableCluster;
	protected ICFSecISOCcyTable tableISOCcy;
	protected ICFSecISOCtryTable tableISOCtry;
	protected ICFSecISOCtryCcyTable tableISOCtryCcy;
	protected ICFSecISOCtryLangTable tableISOCtryLang;
	protected ICFSecISOLangTable tableISOLang;
	protected ICFSecISOTZoneTable tableISOTZone;
	protected ICFSecSecClusGrpTable tableSecClusGrp;
	protected ICFSecSecClusGrpMembTable tableSecClusGrpMemb;
	protected ICFSecSecClusRoleTable tableSecClusRole;
	protected ICFSecSecClusRoleMembTable tableSecClusRoleMemb;
	protected ICFSecSecSessionTable tableSecSession;
	protected ICFSecSecSysGrpTable tableSecSysGrp;
	protected ICFSecSecSysGrpIncTable tableSecSysGrpInc;
	protected ICFSecSecSysGrpMembTable tableSecSysGrpMemb;
	protected ICFSecSecSysRoleTable tableSecSysRole;
	protected ICFSecSecSysRoleEnablesTable tableSecSysRoleEnables;
	protected ICFSecSecSysRoleMembTable tableSecSysRoleMemb;
	protected ICFSecSecTentGrpTable tableSecTentGrp;
	protected ICFSecSecTentGrpMembTable tableSecTentGrpMemb;
	protected ICFSecSecTentRoleTable tableSecTentRole;
	protected ICFSecSecTentRoleMembTable tableSecTentRoleMemb;
	protected ICFSecSecUserTable tableSecUser;
	protected ICFSecSecUserEMConfTable tableSecUserEMConf;
	protected ICFSecSecUserPWHistoryTable tableSecUserPWHistory;
	protected ICFSecSecUserPWResetTable tableSecUserPWReset;
	protected ICFSecSecUserPasswordTable tableSecUserPassword;
	protected ICFSecSysClusterTable tableSysCluster;
	protected ICFSecTableInfoTable tableTableInfo;
	protected ICFSecTenantTable tableTenant;

	protected ICFSecClusterFactory factoryCluster;
	protected ICFSecISOCcyFactory factoryISOCcy;
	protected ICFSecISOCtryFactory factoryISOCtry;
	protected ICFSecISOCtryCcyFactory factoryISOCtryCcy;
	protected ICFSecISOCtryLangFactory factoryISOCtryLang;
	protected ICFSecISOLangFactory factoryISOLang;
	protected ICFSecISOTZoneFactory factoryISOTZone;
	protected ICFSecSecClusGrpFactory factorySecClusGrp;
	protected ICFSecSecClusGrpMembFactory factorySecClusGrpMemb;
	protected ICFSecSecClusRoleFactory factorySecClusRole;
	protected ICFSecSecClusRoleMembFactory factorySecClusRoleMemb;
	protected ICFSecSecSessionFactory factorySecSession;
	protected ICFSecSecSysGrpFactory factorySecSysGrp;
	protected ICFSecSecSysGrpIncFactory factorySecSysGrpInc;
	protected ICFSecSecSysGrpMembFactory factorySecSysGrpMemb;
	protected ICFSecSecSysRoleFactory factorySecSysRole;
	protected ICFSecSecSysRoleEnablesFactory factorySecSysRoleEnables;
	protected ICFSecSecSysRoleMembFactory factorySecSysRoleMemb;
	protected ICFSecSecTentGrpFactory factorySecTentGrp;
	protected ICFSecSecTentGrpMembFactory factorySecTentGrpMemb;
	protected ICFSecSecTentRoleFactory factorySecTentRole;
	protected ICFSecSecTentRoleMembFactory factorySecTentRoleMemb;
	protected ICFSecSecUserFactory factorySecUser;
	protected ICFSecSecUserEMConfFactory factorySecUserEMConf;
	protected ICFSecSecUserPWHistoryFactory factorySecUserPWHistory;
	protected ICFSecSecUserPWResetFactory factorySecUserPWReset;
	protected ICFSecSecUserPasswordFactory factorySecUserPassword;
	protected ICFSecSysClusterFactory factorySysCluster;
	protected ICFSecTableInfoFactory factoryTableInfo;
	protected ICFSecTenantFactory factoryTenant;


	@Override
	public int initClassMapEntries(int value) {
		return( ICFSecSchema.doInitClassMapEntries(value) );
	}

	@Override
	public void wireRecConstructors() {
		ICFSecSchema.ClassMapEntry entry;
		entry = ICFSecSchema.getClassMapByBackingClassCode(ICFSecCluster.CLASS_CODE);
		if (entry != null) {
			entry.setBackingRecConstructor( new BackingRecConstructor() {
				@Override
				public Object instantiate() {
					ICFSecCluster ret = new CFSecJpaCluster();
					return(ret);
				}
			});
		}
		else {
			throw new CFLibNullArgumentException(CFSecJpaSchema.class, "wireRecConstructors", 0, "ICFSecSchema.getClassMapByBackingClassCode(ICFSecCluster.CLASS_CODE)[" + ICFSecCluster.CLASS_CODE + "]");
		}
	
		entry = ICFSecSchema.getClassMapByBackingClassCode(ICFSecTenant.CLASS_CODE);
		if (entry != null) {
			entry.setBackingRecConstructor( new BackingRecConstructor() {
				@Override
				public Object instantiate() {
					ICFSecTenant ret = new CFSecJpaTenant();
					return(ret);
				}
			});
		}
		else {
			throw new CFLibNullArgumentException(CFSecJpaSchema.class, "wireRecConstructors", 0, "ICFSecSchema.getClassMapByBackingClassCode(ICFSecTenant.CLASS_CODE)[" + ICFSecTenant.CLASS_CODE + "]");
		}
	
		entry = ICFSecSchema.getClassMapByBackingClassCode(ICFSecTableInfo.CLASS_CODE);
		if (entry != null) {
			entry.setBackingRecConstructor( new BackingRecConstructor() {
				@Override
				public Object instantiate() {
					ICFSecTableInfo ret = new CFSecJpaTableInfo();
					return(ret);
				}
			});
		}
		else {
			throw new CFLibNullArgumentException(CFSecJpaSchema.class, "wireRecConstructors", 0, "ICFSecSchema.getClassMapByBackingClassCode(ICFSecTableInfo.CLASS_CODE)[" + ICFSecTableInfo.CLASS_CODE + "]");
		}
	
		entry = ICFSecSchema.getClassMapByBackingClassCode(ICFSecISOCcy.CLASS_CODE);
		if (entry != null) {
			entry.setBackingRecConstructor( new BackingRecConstructor() {
				@Override
				public Object instantiate() {
					ICFSecISOCcy ret = new CFSecJpaISOCcy();
					return(ret);
				}
			});
		}
		else {
			throw new CFLibNullArgumentException(CFSecJpaSchema.class, "wireRecConstructors", 0, "ICFSecSchema.getClassMapByBackingClassCode(ICFSecISOCcy.CLASS_CODE)[" + ICFSecISOCcy.CLASS_CODE + "]");
		}
	
		entry = ICFSecSchema.getClassMapByBackingClassCode(ICFSecISOCtry.CLASS_CODE);
		if (entry != null) {
			entry.setBackingRecConstructor( new BackingRecConstructor() {
				@Override
				public Object instantiate() {
					ICFSecISOCtry ret = new CFSecJpaISOCtry();
					return(ret);
				}
			});
		}
		else {
			throw new CFLibNullArgumentException(CFSecJpaSchema.class, "wireRecConstructors", 0, "ICFSecSchema.getClassMapByBackingClassCode(ICFSecISOCtry.CLASS_CODE)[" + ICFSecISOCtry.CLASS_CODE + "]");
		}
	
		entry = ICFSecSchema.getClassMapByBackingClassCode(ICFSecISOCtryCcy.CLASS_CODE);
		if (entry != null) {
			entry.setBackingRecConstructor( new BackingRecConstructor() {
				@Override
				public Object instantiate() {
					ICFSecISOCtryCcy ret = new CFSecJpaISOCtryCcy();
					return(ret);
				}
			});
		}
		else {
			throw new CFLibNullArgumentException(CFSecJpaSchema.class, "wireRecConstructors", 0, "ICFSecSchema.getClassMapByBackingClassCode(ICFSecISOCtryCcy.CLASS_CODE)[" + ICFSecISOCtryCcy.CLASS_CODE + "]");
		}
	
		entry = ICFSecSchema.getClassMapByBackingClassCode(ICFSecISOCtryLang.CLASS_CODE);
		if (entry != null) {
			entry.setBackingRecConstructor( new BackingRecConstructor() {
				@Override
				public Object instantiate() {
					ICFSecISOCtryLang ret = new CFSecJpaISOCtryLang();
					return(ret);
				}
			});
		}
		else {
			throw new CFLibNullArgumentException(CFSecJpaSchema.class, "wireRecConstructors", 0, "ICFSecSchema.getClassMapByBackingClassCode(ICFSecISOCtryLang.CLASS_CODE)[" + ICFSecISOCtryLang.CLASS_CODE + "]");
		}
	
		entry = ICFSecSchema.getClassMapByBackingClassCode(ICFSecISOLang.CLASS_CODE);
		if (entry != null) {
			entry.setBackingRecConstructor( new BackingRecConstructor() {
				@Override
				public Object instantiate() {
					ICFSecISOLang ret = new CFSecJpaISOLang();
					return(ret);
				}
			});
		}
		else {
			throw new CFLibNullArgumentException(CFSecJpaSchema.class, "wireRecConstructors", 0, "ICFSecSchema.getClassMapByBackingClassCode(ICFSecISOLang.CLASS_CODE)[" + ICFSecISOLang.CLASS_CODE + "]");
		}
	
		entry = ICFSecSchema.getClassMapByBackingClassCode(ICFSecISOTZone.CLASS_CODE);
		if (entry != null) {
			entry.setBackingRecConstructor( new BackingRecConstructor() {
				@Override
				public Object instantiate() {
					ICFSecISOTZone ret = new CFSecJpaISOTZone();
					return(ret);
				}
			});
		}
		else {
			throw new CFLibNullArgumentException(CFSecJpaSchema.class, "wireRecConstructors", 0, "ICFSecSchema.getClassMapByBackingClassCode(ICFSecISOTZone.CLASS_CODE)[" + ICFSecISOTZone.CLASS_CODE + "]");
		}
	
		entry = ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecUser.CLASS_CODE);
		if (entry != null) {
			entry.setBackingRecConstructor( new BackingRecConstructor() {
				@Override
				public Object instantiate() {
					ICFSecSecUser ret = new CFSecJpaSecUser();
					return(ret);
				}
			});
		}
		else {
			throw new CFLibNullArgumentException(CFSecJpaSchema.class, "wireRecConstructors", 0, "ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecUser.CLASS_CODE)[" + ICFSecSecUser.CLASS_CODE + "]");
		}
	
		entry = ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecUserPassword.CLASS_CODE);
		if (entry != null) {
			entry.setBackingRecConstructor( new BackingRecConstructor() {
				@Override
				public Object instantiate() {
					ICFSecSecUserPassword ret = new CFSecJpaSecUserPassword();
					return(ret);
				}
			});
		}
		else {
			throw new CFLibNullArgumentException(CFSecJpaSchema.class, "wireRecConstructors", 0, "ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecUserPassword.CLASS_CODE)[" + ICFSecSecUserPassword.CLASS_CODE + "]");
		}
	
		entry = ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecUserEMConf.CLASS_CODE);
		if (entry != null) {
			entry.setBackingRecConstructor( new BackingRecConstructor() {
				@Override
				public Object instantiate() {
					ICFSecSecUserEMConf ret = new CFSecJpaSecUserEMConf();
					return(ret);
				}
			});
		}
		else {
			throw new CFLibNullArgumentException(CFSecJpaSchema.class, "wireRecConstructors", 0, "ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecUserEMConf.CLASS_CODE)[" + ICFSecSecUserEMConf.CLASS_CODE + "]");
		}
	
		entry = ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecUserPWReset.CLASS_CODE);
		if (entry != null) {
			entry.setBackingRecConstructor( new BackingRecConstructor() {
				@Override
				public Object instantiate() {
					ICFSecSecUserPWReset ret = new CFSecJpaSecUserPWReset();
					return(ret);
				}
			});
		}
		else {
			throw new CFLibNullArgumentException(CFSecJpaSchema.class, "wireRecConstructors", 0, "ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecUserPWReset.CLASS_CODE)[" + ICFSecSecUserPWReset.CLASS_CODE + "]");
		}
	
		entry = ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecUserPWHistory.CLASS_CODE);
		if (entry != null) {
			entry.setBackingRecConstructor( new BackingRecConstructor() {
				@Override
				public Object instantiate() {
					ICFSecSecUserPWHistory ret = new CFSecJpaSecUserPWHistory();
					return(ret);
				}
			});
		}
		else {
			throw new CFLibNullArgumentException(CFSecJpaSchema.class, "wireRecConstructors", 0, "ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecUserPWHistory.CLASS_CODE)[" + ICFSecSecUserPWHistory.CLASS_CODE + "]");
		}
	
		entry = ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecSysGrp.CLASS_CODE);
		if (entry != null) {
			entry.setBackingRecConstructor( new BackingRecConstructor() {
				@Override
				public Object instantiate() {
					ICFSecSecSysGrp ret = new CFSecJpaSecSysGrp();
					return(ret);
				}
			});
		}
		else {
			throw new CFLibNullArgumentException(CFSecJpaSchema.class, "wireRecConstructors", 0, "ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecSysGrp.CLASS_CODE)[" + ICFSecSecSysGrp.CLASS_CODE + "]");
		}
	
		entry = ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecSysGrpInc.CLASS_CODE);
		if (entry != null) {
			entry.setBackingRecConstructor( new BackingRecConstructor() {
				@Override
				public Object instantiate() {
					ICFSecSecSysGrpInc ret = new CFSecJpaSecSysGrpInc();
					return(ret);
				}
			});
		}
		else {
			throw new CFLibNullArgumentException(CFSecJpaSchema.class, "wireRecConstructors", 0, "ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecSysGrpInc.CLASS_CODE)[" + ICFSecSecSysGrpInc.CLASS_CODE + "]");
		}
	
		entry = ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecSysGrpMemb.CLASS_CODE);
		if (entry != null) {
			entry.setBackingRecConstructor( new BackingRecConstructor() {
				@Override
				public Object instantiate() {
					ICFSecSecSysGrpMemb ret = new CFSecJpaSecSysGrpMemb();
					return(ret);
				}
			});
		}
		else {
			throw new CFLibNullArgumentException(CFSecJpaSchema.class, "wireRecConstructors", 0, "ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecSysGrpMemb.CLASS_CODE)[" + ICFSecSecSysGrpMemb.CLASS_CODE + "]");
		}
	
		entry = ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecClusGrp.CLASS_CODE);
		if (entry != null) {
			entry.setBackingRecConstructor( new BackingRecConstructor() {
				@Override
				public Object instantiate() {
					ICFSecSecClusGrp ret = new CFSecJpaSecClusGrp();
					return(ret);
				}
			});
		}
		else {
			throw new CFLibNullArgumentException(CFSecJpaSchema.class, "wireRecConstructors", 0, "ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecClusGrp.CLASS_CODE)[" + ICFSecSecClusGrp.CLASS_CODE + "]");
		}
	
		entry = ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecClusGrpMemb.CLASS_CODE);
		if (entry != null) {
			entry.setBackingRecConstructor( new BackingRecConstructor() {
				@Override
				public Object instantiate() {
					ICFSecSecClusGrpMemb ret = new CFSecJpaSecClusGrpMemb();
					return(ret);
				}
			});
		}
		else {
			throw new CFLibNullArgumentException(CFSecJpaSchema.class, "wireRecConstructors", 0, "ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecClusGrpMemb.CLASS_CODE)[" + ICFSecSecClusGrpMemb.CLASS_CODE + "]");
		}
	
		entry = ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecTentGrp.CLASS_CODE);
		if (entry != null) {
			entry.setBackingRecConstructor( new BackingRecConstructor() {
				@Override
				public Object instantiate() {
					ICFSecSecTentGrp ret = new CFSecJpaSecTentGrp();
					return(ret);
				}
			});
		}
		else {
			throw new CFLibNullArgumentException(CFSecJpaSchema.class, "wireRecConstructors", 0, "ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecTentGrp.CLASS_CODE)[" + ICFSecSecTentGrp.CLASS_CODE + "]");
		}
	
		entry = ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecTentGrpMemb.CLASS_CODE);
		if (entry != null) {
			entry.setBackingRecConstructor( new BackingRecConstructor() {
				@Override
				public Object instantiate() {
					ICFSecSecTentGrpMemb ret = new CFSecJpaSecTentGrpMemb();
					return(ret);
				}
			});
		}
		else {
			throw new CFLibNullArgumentException(CFSecJpaSchema.class, "wireRecConstructors", 0, "ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecTentGrpMemb.CLASS_CODE)[" + ICFSecSecTentGrpMemb.CLASS_CODE + "]");
		}
	
		entry = ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecSysRole.CLASS_CODE);
		if (entry != null) {
			entry.setBackingRecConstructor( new BackingRecConstructor() {
				@Override
				public Object instantiate() {
					ICFSecSecSysRole ret = new CFSecJpaSecSysRole();
					return(ret);
				}
			});
		}
		else {
			throw new CFLibNullArgumentException(CFSecJpaSchema.class, "wireRecConstructors", 0, "ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecSysRole.CLASS_CODE)[" + ICFSecSecSysRole.CLASS_CODE + "]");
		}
	
		entry = ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecSysRoleEnables.CLASS_CODE);
		if (entry != null) {
			entry.setBackingRecConstructor( new BackingRecConstructor() {
				@Override
				public Object instantiate() {
					ICFSecSecSysRoleEnables ret = new CFSecJpaSecSysRoleEnables();
					return(ret);
				}
			});
		}
		else {
			throw new CFLibNullArgumentException(CFSecJpaSchema.class, "wireRecConstructors", 0, "ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecSysRoleEnables.CLASS_CODE)[" + ICFSecSecSysRoleEnables.CLASS_CODE + "]");
		}
	
		entry = ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecSysRoleMemb.CLASS_CODE);
		if (entry != null) {
			entry.setBackingRecConstructor( new BackingRecConstructor() {
				@Override
				public Object instantiate() {
					ICFSecSecSysRoleMemb ret = new CFSecJpaSecSysRoleMemb();
					return(ret);
				}
			});
		}
		else {
			throw new CFLibNullArgumentException(CFSecJpaSchema.class, "wireRecConstructors", 0, "ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecSysRoleMemb.CLASS_CODE)[" + ICFSecSecSysRoleMemb.CLASS_CODE + "]");
		}
	
		entry = ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecClusRole.CLASS_CODE);
		if (entry != null) {
			entry.setBackingRecConstructor( new BackingRecConstructor() {
				@Override
				public Object instantiate() {
					ICFSecSecClusRole ret = new CFSecJpaSecClusRole();
					return(ret);
				}
			});
		}
		else {
			throw new CFLibNullArgumentException(CFSecJpaSchema.class, "wireRecConstructors", 0, "ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecClusRole.CLASS_CODE)[" + ICFSecSecClusRole.CLASS_CODE + "]");
		}
	
		entry = ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecClusRoleMemb.CLASS_CODE);
		if (entry != null) {
			entry.setBackingRecConstructor( new BackingRecConstructor() {
				@Override
				public Object instantiate() {
					ICFSecSecClusRoleMemb ret = new CFSecJpaSecClusRoleMemb();
					return(ret);
				}
			});
		}
		else {
			throw new CFLibNullArgumentException(CFSecJpaSchema.class, "wireRecConstructors", 0, "ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecClusRoleMemb.CLASS_CODE)[" + ICFSecSecClusRoleMemb.CLASS_CODE + "]");
		}
	
		entry = ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecTentRole.CLASS_CODE);
		if (entry != null) {
			entry.setBackingRecConstructor( new BackingRecConstructor() {
				@Override
				public Object instantiate() {
					ICFSecSecTentRole ret = new CFSecJpaSecTentRole();
					return(ret);
				}
			});
		}
		else {
			throw new CFLibNullArgumentException(CFSecJpaSchema.class, "wireRecConstructors", 0, "ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecTentRole.CLASS_CODE)[" + ICFSecSecTentRole.CLASS_CODE + "]");
		}
	
		entry = ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecTentRoleMemb.CLASS_CODE);
		if (entry != null) {
			entry.setBackingRecConstructor( new BackingRecConstructor() {
				@Override
				public Object instantiate() {
					ICFSecSecTentRoleMemb ret = new CFSecJpaSecTentRoleMemb();
					return(ret);
				}
			});
		}
		else {
			throw new CFLibNullArgumentException(CFSecJpaSchema.class, "wireRecConstructors", 0, "ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecTentRoleMemb.CLASS_CODE)[" + ICFSecSecTentRoleMemb.CLASS_CODE + "]");
		}
	
		entry = ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecSession.CLASS_CODE);
		if (entry != null) {
			entry.setBackingRecConstructor( new BackingRecConstructor() {
				@Override
				public Object instantiate() {
					ICFSecSecSession ret = new CFSecJpaSecSession();
					return(ret);
				}
			});
		}
		else {
			throw new CFLibNullArgumentException(CFSecJpaSchema.class, "wireRecConstructors", 0, "ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecSession.CLASS_CODE)[" + ICFSecSecSession.CLASS_CODE + "]");
		}
	
		entry = ICFSecSchema.getClassMapByBackingClassCode(ICFSecSysCluster.CLASS_CODE);
		if (entry != null) {
			entry.setBackingRecConstructor( new BackingRecConstructor() {
				@Override
				public Object instantiate() {
					ICFSecSysCluster ret = new CFSecJpaSysCluster();
					return(ret);
				}
			});
		}
		else {
			throw new CFLibNullArgumentException(CFSecJpaSchema.class, "wireRecConstructors", 0, "ICFSecSchema.getClassMapByBackingClassCode(ICFSecSysCluster.CLASS_CODE)[" + ICFSecSysCluster.CLASS_CODE + "]");
		}
	
	}

	@Override
	public void wireTableTableInstances() {
		if (tableCluster == null || !(tableCluster instanceof CFSecJpaClusterTable)) {
			tableCluster = new CFSecJpaClusterTable(this);
		}
		if (tableTenant == null || !(tableTenant instanceof CFSecJpaTenantTable)) {
			tableTenant = new CFSecJpaTenantTable(this);
		}
		if (tableTableInfo == null || !(tableTableInfo instanceof CFSecJpaTableInfoTable)) {
			tableTableInfo = new CFSecJpaTableInfoTable(this);
		}
		if (tableISOCcy == null || !(tableISOCcy instanceof CFSecJpaISOCcyTable)) {
			tableISOCcy = new CFSecJpaISOCcyTable(this);
		}
		if (tableISOCtry == null || !(tableISOCtry instanceof CFSecJpaISOCtryTable)) {
			tableISOCtry = new CFSecJpaISOCtryTable(this);
		}
		if (tableISOCtryCcy == null || !(tableISOCtryCcy instanceof CFSecJpaISOCtryCcyTable)) {
			tableISOCtryCcy = new CFSecJpaISOCtryCcyTable(this);
		}
		if (tableISOCtryLang == null || !(tableISOCtryLang instanceof CFSecJpaISOCtryLangTable)) {
			tableISOCtryLang = new CFSecJpaISOCtryLangTable(this);
		}
		if (tableISOLang == null || !(tableISOLang instanceof CFSecJpaISOLangTable)) {
			tableISOLang = new CFSecJpaISOLangTable(this);
		}
		if (tableISOTZone == null || !(tableISOTZone instanceof CFSecJpaISOTZoneTable)) {
			tableISOTZone = new CFSecJpaISOTZoneTable(this);
		}
		if (tableSecUser == null || !(tableSecUser instanceof CFSecJpaSecUserTable)) {
			tableSecUser = new CFSecJpaSecUserTable(this);
		}
		if (tableSecUserPassword == null || !(tableSecUserPassword instanceof CFSecJpaSecUserPasswordTable)) {
			tableSecUserPassword = new CFSecJpaSecUserPasswordTable(this);
		}
		if (tableSecUserEMConf == null || !(tableSecUserEMConf instanceof CFSecJpaSecUserEMConfTable)) {
			tableSecUserEMConf = new CFSecJpaSecUserEMConfTable(this);
		}
		if (tableSecUserPWReset == null || !(tableSecUserPWReset instanceof CFSecJpaSecUserPWResetTable)) {
			tableSecUserPWReset = new CFSecJpaSecUserPWResetTable(this);
		}
		if (tableSecUserPWHistory == null || !(tableSecUserPWHistory instanceof CFSecJpaSecUserPWHistoryTable)) {
			tableSecUserPWHistory = new CFSecJpaSecUserPWHistoryTable(this);
		}
		if (tableSecSysGrp == null || !(tableSecSysGrp instanceof CFSecJpaSecSysGrpTable)) {
			tableSecSysGrp = new CFSecJpaSecSysGrpTable(this);
		}
		if (tableSecSysGrpInc == null || !(tableSecSysGrpInc instanceof CFSecJpaSecSysGrpIncTable)) {
			tableSecSysGrpInc = new CFSecJpaSecSysGrpIncTable(this);
		}
		if (tableSecSysGrpMemb == null || !(tableSecSysGrpMemb instanceof CFSecJpaSecSysGrpMembTable)) {
			tableSecSysGrpMemb = new CFSecJpaSecSysGrpMembTable(this);
		}
		if (tableSecClusGrp == null || !(tableSecClusGrp instanceof CFSecJpaSecClusGrpTable)) {
			tableSecClusGrp = new CFSecJpaSecClusGrpTable(this);
		}
		if (tableSecClusGrpMemb == null || !(tableSecClusGrpMemb instanceof CFSecJpaSecClusGrpMembTable)) {
			tableSecClusGrpMemb = new CFSecJpaSecClusGrpMembTable(this);
		}
		if (tableSecTentGrp == null || !(tableSecTentGrp instanceof CFSecJpaSecTentGrpTable)) {
			tableSecTentGrp = new CFSecJpaSecTentGrpTable(this);
		}
		if (tableSecTentGrpMemb == null || !(tableSecTentGrpMemb instanceof CFSecJpaSecTentGrpMembTable)) {
			tableSecTentGrpMemb = new CFSecJpaSecTentGrpMembTable(this);
		}
		if (tableSecSysRole == null || !(tableSecSysRole instanceof CFSecJpaSecSysRoleTable)) {
			tableSecSysRole = new CFSecJpaSecSysRoleTable(this);
		}
		if (tableSecSysRoleEnables == null || !(tableSecSysRoleEnables instanceof CFSecJpaSecSysRoleEnablesTable)) {
			tableSecSysRoleEnables = new CFSecJpaSecSysRoleEnablesTable(this);
		}
		if (tableSecSysRoleMemb == null || !(tableSecSysRoleMemb instanceof CFSecJpaSecSysRoleMembTable)) {
			tableSecSysRoleMemb = new CFSecJpaSecSysRoleMembTable(this);
		}
		if (tableSecClusRole == null || !(tableSecClusRole instanceof CFSecJpaSecClusRoleTable)) {
			tableSecClusRole = new CFSecJpaSecClusRoleTable(this);
		}
		if (tableSecClusRoleMemb == null || !(tableSecClusRoleMemb instanceof CFSecJpaSecClusRoleMembTable)) {
			tableSecClusRoleMemb = new CFSecJpaSecClusRoleMembTable(this);
		}
		if (tableSecTentRole == null || !(tableSecTentRole instanceof CFSecJpaSecTentRoleTable)) {
			tableSecTentRole = new CFSecJpaSecTentRoleTable(this);
		}
		if (tableSecTentRoleMemb == null || !(tableSecTentRoleMemb instanceof CFSecJpaSecTentRoleMembTable)) {
			tableSecTentRoleMemb = new CFSecJpaSecTentRoleMembTable(this);
		}
		if (tableSecSession == null || !(tableSecSession instanceof CFSecJpaSecSessionTable)) {
			tableSecSession = new CFSecJpaSecSessionTable(this);
		}
		if (tableSysCluster == null || !(tableSysCluster instanceof CFSecJpaSysClusterTable)) {
			tableSysCluster = new CFSecJpaSysClusterTable(this);
		}
	}

	@Override		
	public ICFSecSchema getCFSecSchema() {
		return( ICFSecSchema.getBackingCFSec() );
	}

	@Override
	public void setCFSecSchema(ICFSecSchema schema) {
		ICFSecSchema.setBackingCFSec(schema);
		schema.wireRecConstructors();
	}

	public CFSecJpaHooksSchema getJpaHooksSchema() {
		return( cfsecJpaHooksSchema );
	}

	public void setJpaHooksSchema(CFSecJpaHooksSchema jpaHooksSchema) {
		cfsecJpaHooksSchema = jpaHooksSchema;
	}

	public CFSecJpaSchemaService getSchemaService() {
		return( getJpaHooksSchema().getSchemaService() );
	}

	public CFSecJpaSchema() {

		tableCluster = null;
		tableISOCcy = null;
		tableISOCtry = null;
		tableISOCtryCcy = null;
		tableISOCtryLang = null;
		tableISOLang = null;
		tableISOTZone = null;
		tableSecClusGrp = null;
		tableSecClusGrpMemb = null;
		tableSecClusRole = null;
		tableSecClusRoleMemb = null;
		tableSecSession = null;
		tableSecSysGrp = null;
		tableSecSysGrpInc = null;
		tableSecSysGrpMemb = null;
		tableSecSysRole = null;
		tableSecSysRoleEnables = null;
		tableSecSysRoleMemb = null;
		tableSecTentGrp = null;
		tableSecTentGrpMemb = null;
		tableSecTentRole = null;
		tableSecTentRoleMemb = null;
		tableSecUser = null;
		tableSecUserEMConf = null;
		tableSecUserPWHistory = null;
		tableSecUserPWReset = null;
		tableSecUserPassword = null;
		tableSysCluster = null;
		tableTableInfo = null;
		tableTenant = null;

		factoryCluster = new CFSecJpaClusterDefaultFactory();
		factoryISOCcy = new CFSecJpaISOCcyDefaultFactory();
		factoryISOCtry = new CFSecJpaISOCtryDefaultFactory();
		factoryISOCtryCcy = new CFSecJpaISOCtryCcyDefaultFactory();
		factoryISOCtryLang = new CFSecJpaISOCtryLangDefaultFactory();
		factoryISOLang = new CFSecJpaISOLangDefaultFactory();
		factoryISOTZone = new CFSecJpaISOTZoneDefaultFactory();
		factorySecClusGrp = new CFSecJpaSecClusGrpDefaultFactory();
		factorySecClusGrpMemb = new CFSecJpaSecClusGrpMembDefaultFactory();
		factorySecClusRole = new CFSecJpaSecClusRoleDefaultFactory();
		factorySecClusRoleMemb = new CFSecJpaSecClusRoleMembDefaultFactory();
		factorySecSession = new CFSecJpaSecSessionDefaultFactory();
		factorySecSysGrp = new CFSecJpaSecSysGrpDefaultFactory();
		factorySecSysGrpInc = new CFSecJpaSecSysGrpIncDefaultFactory();
		factorySecSysGrpMemb = new CFSecJpaSecSysGrpMembDefaultFactory();
		factorySecSysRole = new CFSecJpaSecSysRoleDefaultFactory();
		factorySecSysRoleEnables = new CFSecJpaSecSysRoleEnablesDefaultFactory();
		factorySecSysRoleMemb = new CFSecJpaSecSysRoleMembDefaultFactory();
		factorySecTentGrp = new CFSecJpaSecTentGrpDefaultFactory();
		factorySecTentGrpMemb = new CFSecJpaSecTentGrpMembDefaultFactory();
		factorySecTentRole = new CFSecJpaSecTentRoleDefaultFactory();
		factorySecTentRoleMemb = new CFSecJpaSecTentRoleMembDefaultFactory();
		factorySecUser = new CFSecJpaSecUserDefaultFactory();
		factorySecUserEMConf = new CFSecJpaSecUserEMConfDefaultFactory();
		factorySecUserPWHistory = new CFSecJpaSecUserPWHistoryDefaultFactory();
		factorySecUserPWReset = new CFSecJpaSecUserPWResetDefaultFactory();
		factorySecUserPassword = new CFSecJpaSecUserPasswordDefaultFactory();
		factorySysCluster = new CFSecJpaSysClusterDefaultFactory();
		factoryTableInfo = new CFSecJpaTableInfoDefaultFactory();
		factoryTenant = new CFSecJpaTenantDefaultFactory();	}

	@Override
	public ICFSecSchema newSchema() {
		throw new CFLibMustOverrideException( getClass(), "newSchema" );
	}

	@Override
	public short nextISOCcyIdGen() {
		throw new CFLibNotImplementedYetException( getClass(), "nextISOCcyIdGen" );
	}

	@Override
	public short nextISOCtryIdGen() {
		throw new CFLibNotImplementedYetException( getClass(), "nextISOCtryIdGen" );
	}

	@Override
	public short nextISOLangIdGen() {
		throw new CFLibNotImplementedYetException( getClass(), "nextISOLangIdGen" );
	}

	@Override
	public short nextISOTZoneIdGen() {
		throw new CFLibNotImplementedYetException( getClass(), "nextISOTZoneIdGen" );
	}

	@Override
	public int nextTableInfoIdGen() {
		throw new CFLibNotImplementedYetException( getClass(), "nextTableInfoIdGen" );
	}

	@Override
	public CFLibDbKeyHash256 nextClusterIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextSecSessionIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextSecUserIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextTenantIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextSecSysGrpIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextSecClusGrpIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextSecClusRoleIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextSecTentGrpIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextSecTentRoleIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	public ICFSecClusterTable getTableCluster() {
		return( tableCluster );
	}

	public void setTableCluster( ICFSecClusterTable value ) {
		tableCluster = value;
	}

	public ICFSecClusterFactory getFactoryCluster() {
		return( factoryCluster );
	}

	public void setFactoryCluster( ICFSecClusterFactory value ) {
		factoryCluster = value;
	}

	public ICFSecISOCcyTable getTableISOCcy() {
		return( tableISOCcy );
	}

	public void setTableISOCcy( ICFSecISOCcyTable value ) {
		tableISOCcy = value;
	}

	public ICFSecISOCcyFactory getFactoryISOCcy() {
		return( factoryISOCcy );
	}

	public void setFactoryISOCcy( ICFSecISOCcyFactory value ) {
		factoryISOCcy = value;
	}

	public ICFSecISOCtryTable getTableISOCtry() {
		return( tableISOCtry );
	}

	public void setTableISOCtry( ICFSecISOCtryTable value ) {
		tableISOCtry = value;
	}

	public ICFSecISOCtryFactory getFactoryISOCtry() {
		return( factoryISOCtry );
	}

	public void setFactoryISOCtry( ICFSecISOCtryFactory value ) {
		factoryISOCtry = value;
	}

	public ICFSecISOCtryCcyTable getTableISOCtryCcy() {
		return( tableISOCtryCcy );
	}

	public void setTableISOCtryCcy( ICFSecISOCtryCcyTable value ) {
		tableISOCtryCcy = value;
	}

	public ICFSecISOCtryCcyFactory getFactoryISOCtryCcy() {
		return( factoryISOCtryCcy );
	}

	public void setFactoryISOCtryCcy( ICFSecISOCtryCcyFactory value ) {
		factoryISOCtryCcy = value;
	}

	public ICFSecISOCtryLangTable getTableISOCtryLang() {
		return( tableISOCtryLang );
	}

	public void setTableISOCtryLang( ICFSecISOCtryLangTable value ) {
		tableISOCtryLang = value;
	}

	public ICFSecISOCtryLangFactory getFactoryISOCtryLang() {
		return( factoryISOCtryLang );
	}

	public void setFactoryISOCtryLang( ICFSecISOCtryLangFactory value ) {
		factoryISOCtryLang = value;
	}

	public ICFSecISOLangTable getTableISOLang() {
		return( tableISOLang );
	}

	public void setTableISOLang( ICFSecISOLangTable value ) {
		tableISOLang = value;
	}

	public ICFSecISOLangFactory getFactoryISOLang() {
		return( factoryISOLang );
	}

	public void setFactoryISOLang( ICFSecISOLangFactory value ) {
		factoryISOLang = value;
	}

	public ICFSecISOTZoneTable getTableISOTZone() {
		return( tableISOTZone );
	}

	public void setTableISOTZone( ICFSecISOTZoneTable value ) {
		tableISOTZone = value;
	}

	public ICFSecISOTZoneFactory getFactoryISOTZone() {
		return( factoryISOTZone );
	}

	public void setFactoryISOTZone( ICFSecISOTZoneFactory value ) {
		factoryISOTZone = value;
	}

	public ICFSecSecClusGrpTable getTableSecClusGrp() {
		return( tableSecClusGrp );
	}

	public void setTableSecClusGrp( ICFSecSecClusGrpTable value ) {
		tableSecClusGrp = value;
	}

	public ICFSecSecClusGrpFactory getFactorySecClusGrp() {
		return( factorySecClusGrp );
	}

	public void setFactorySecClusGrp( ICFSecSecClusGrpFactory value ) {
		factorySecClusGrp = value;
	}

	public ICFSecSecClusGrpMembTable getTableSecClusGrpMemb() {
		return( tableSecClusGrpMemb );
	}

	public void setTableSecClusGrpMemb( ICFSecSecClusGrpMembTable value ) {
		tableSecClusGrpMemb = value;
	}

	public ICFSecSecClusGrpMembFactory getFactorySecClusGrpMemb() {
		return( factorySecClusGrpMemb );
	}

	public void setFactorySecClusGrpMemb( ICFSecSecClusGrpMembFactory value ) {
		factorySecClusGrpMemb = value;
	}

	public ICFSecSecClusRoleTable getTableSecClusRole() {
		return( tableSecClusRole );
	}

	public void setTableSecClusRole( ICFSecSecClusRoleTable value ) {
		tableSecClusRole = value;
	}

	public ICFSecSecClusRoleFactory getFactorySecClusRole() {
		return( factorySecClusRole );
	}

	public void setFactorySecClusRole( ICFSecSecClusRoleFactory value ) {
		factorySecClusRole = value;
	}

	public ICFSecSecClusRoleMembTable getTableSecClusRoleMemb() {
		return( tableSecClusRoleMemb );
	}

	public void setTableSecClusRoleMemb( ICFSecSecClusRoleMembTable value ) {
		tableSecClusRoleMemb = value;
	}

	public ICFSecSecClusRoleMembFactory getFactorySecClusRoleMemb() {
		return( factorySecClusRoleMemb );
	}

	public void setFactorySecClusRoleMemb( ICFSecSecClusRoleMembFactory value ) {
		factorySecClusRoleMemb = value;
	}

	public ICFSecSecSessionTable getTableSecSession() {
		return( tableSecSession );
	}

	public void setTableSecSession( ICFSecSecSessionTable value ) {
		tableSecSession = value;
	}

	public ICFSecSecSessionFactory getFactorySecSession() {
		return( factorySecSession );
	}

	public void setFactorySecSession( ICFSecSecSessionFactory value ) {
		factorySecSession = value;
	}

	public ICFSecSecSysGrpTable getTableSecSysGrp() {
		return( tableSecSysGrp );
	}

	public void setTableSecSysGrp( ICFSecSecSysGrpTable value ) {
		tableSecSysGrp = value;
	}

	public ICFSecSecSysGrpFactory getFactorySecSysGrp() {
		return( factorySecSysGrp );
	}

	public void setFactorySecSysGrp( ICFSecSecSysGrpFactory value ) {
		factorySecSysGrp = value;
	}

	public ICFSecSecSysGrpIncTable getTableSecSysGrpInc() {
		return( tableSecSysGrpInc );
	}

	public void setTableSecSysGrpInc( ICFSecSecSysGrpIncTable value ) {
		tableSecSysGrpInc = value;
	}

	public ICFSecSecSysGrpIncFactory getFactorySecSysGrpInc() {
		return( factorySecSysGrpInc );
	}

	public void setFactorySecSysGrpInc( ICFSecSecSysGrpIncFactory value ) {
		factorySecSysGrpInc = value;
	}

	public ICFSecSecSysGrpMembTable getTableSecSysGrpMemb() {
		return( tableSecSysGrpMemb );
	}

	public void setTableSecSysGrpMemb( ICFSecSecSysGrpMembTable value ) {
		tableSecSysGrpMemb = value;
	}

	public ICFSecSecSysGrpMembFactory getFactorySecSysGrpMemb() {
		return( factorySecSysGrpMemb );
	}

	public void setFactorySecSysGrpMemb( ICFSecSecSysGrpMembFactory value ) {
		factorySecSysGrpMemb = value;
	}

	public ICFSecSecSysRoleTable getTableSecSysRole() {
		return( tableSecSysRole );
	}

	public void setTableSecSysRole( ICFSecSecSysRoleTable value ) {
		tableSecSysRole = value;
	}

	public ICFSecSecSysRoleFactory getFactorySecSysRole() {
		return( factorySecSysRole );
	}

	public void setFactorySecSysRole( ICFSecSecSysRoleFactory value ) {
		factorySecSysRole = value;
	}

	public ICFSecSecSysRoleEnablesTable getTableSecSysRoleEnables() {
		return( tableSecSysRoleEnables );
	}

	public void setTableSecSysRoleEnables( ICFSecSecSysRoleEnablesTable value ) {
		tableSecSysRoleEnables = value;
	}

	public ICFSecSecSysRoleEnablesFactory getFactorySecSysRoleEnables() {
		return( factorySecSysRoleEnables );
	}

	public void setFactorySecSysRoleEnables( ICFSecSecSysRoleEnablesFactory value ) {
		factorySecSysRoleEnables = value;
	}

	public ICFSecSecSysRoleMembTable getTableSecSysRoleMemb() {
		return( tableSecSysRoleMemb );
	}

	public void setTableSecSysRoleMemb( ICFSecSecSysRoleMembTable value ) {
		tableSecSysRoleMemb = value;
	}

	public ICFSecSecSysRoleMembFactory getFactorySecSysRoleMemb() {
		return( factorySecSysRoleMemb );
	}

	public void setFactorySecSysRoleMemb( ICFSecSecSysRoleMembFactory value ) {
		factorySecSysRoleMemb = value;
	}

	public ICFSecSecTentGrpTable getTableSecTentGrp() {
		return( tableSecTentGrp );
	}

	public void setTableSecTentGrp( ICFSecSecTentGrpTable value ) {
		tableSecTentGrp = value;
	}

	public ICFSecSecTentGrpFactory getFactorySecTentGrp() {
		return( factorySecTentGrp );
	}

	public void setFactorySecTentGrp( ICFSecSecTentGrpFactory value ) {
		factorySecTentGrp = value;
	}

	public ICFSecSecTentGrpMembTable getTableSecTentGrpMemb() {
		return( tableSecTentGrpMemb );
	}

	public void setTableSecTentGrpMemb( ICFSecSecTentGrpMembTable value ) {
		tableSecTentGrpMemb = value;
	}

	public ICFSecSecTentGrpMembFactory getFactorySecTentGrpMemb() {
		return( factorySecTentGrpMemb );
	}

	public void setFactorySecTentGrpMemb( ICFSecSecTentGrpMembFactory value ) {
		factorySecTentGrpMemb = value;
	}

	public ICFSecSecTentRoleTable getTableSecTentRole() {
		return( tableSecTentRole );
	}

	public void setTableSecTentRole( ICFSecSecTentRoleTable value ) {
		tableSecTentRole = value;
	}

	public ICFSecSecTentRoleFactory getFactorySecTentRole() {
		return( factorySecTentRole );
	}

	public void setFactorySecTentRole( ICFSecSecTentRoleFactory value ) {
		factorySecTentRole = value;
	}

	public ICFSecSecTentRoleMembTable getTableSecTentRoleMemb() {
		return( tableSecTentRoleMemb );
	}

	public void setTableSecTentRoleMemb( ICFSecSecTentRoleMembTable value ) {
		tableSecTentRoleMemb = value;
	}

	public ICFSecSecTentRoleMembFactory getFactorySecTentRoleMemb() {
		return( factorySecTentRoleMemb );
	}

	public void setFactorySecTentRoleMemb( ICFSecSecTentRoleMembFactory value ) {
		factorySecTentRoleMemb = value;
	}

	public ICFSecSecUserTable getTableSecUser() {
		return( tableSecUser );
	}

	public void setTableSecUser( ICFSecSecUserTable value ) {
		tableSecUser = value;
	}

	public ICFSecSecUserFactory getFactorySecUser() {
		return( factorySecUser );
	}

	public void setFactorySecUser( ICFSecSecUserFactory value ) {
		factorySecUser = value;
	}

	public ICFSecSecUserEMConfTable getTableSecUserEMConf() {
		return( tableSecUserEMConf );
	}

	public void setTableSecUserEMConf( ICFSecSecUserEMConfTable value ) {
		tableSecUserEMConf = value;
	}

	public ICFSecSecUserEMConfFactory getFactorySecUserEMConf() {
		return( factorySecUserEMConf );
	}

	public void setFactorySecUserEMConf( ICFSecSecUserEMConfFactory value ) {
		factorySecUserEMConf = value;
	}

	public ICFSecSecUserPWHistoryTable getTableSecUserPWHistory() {
		return( tableSecUserPWHistory );
	}

	public void setTableSecUserPWHistory( ICFSecSecUserPWHistoryTable value ) {
		tableSecUserPWHistory = value;
	}

	public ICFSecSecUserPWHistoryFactory getFactorySecUserPWHistory() {
		return( factorySecUserPWHistory );
	}

	public void setFactorySecUserPWHistory( ICFSecSecUserPWHistoryFactory value ) {
		factorySecUserPWHistory = value;
	}

	public ICFSecSecUserPWResetTable getTableSecUserPWReset() {
		return( tableSecUserPWReset );
	}

	public void setTableSecUserPWReset( ICFSecSecUserPWResetTable value ) {
		tableSecUserPWReset = value;
	}

	public ICFSecSecUserPWResetFactory getFactorySecUserPWReset() {
		return( factorySecUserPWReset );
	}

	public void setFactorySecUserPWReset( ICFSecSecUserPWResetFactory value ) {
		factorySecUserPWReset = value;
	}

	public ICFSecSecUserPasswordTable getTableSecUserPassword() {
		return( tableSecUserPassword );
	}

	public void setTableSecUserPassword( ICFSecSecUserPasswordTable value ) {
		tableSecUserPassword = value;
	}

	public ICFSecSecUserPasswordFactory getFactorySecUserPassword() {
		return( factorySecUserPassword );
	}

	public void setFactorySecUserPassword( ICFSecSecUserPasswordFactory value ) {
		factorySecUserPassword = value;
	}

	public ICFSecSysClusterTable getTableSysCluster() {
		return( tableSysCluster );
	}

	public void setTableSysCluster( ICFSecSysClusterTable value ) {
		tableSysCluster = value;
	}

	public ICFSecSysClusterFactory getFactorySysCluster() {
		return( factorySysCluster );
	}

	public void setFactorySysCluster( ICFSecSysClusterFactory value ) {
		factorySysCluster = value;
	}

	public ICFSecTableInfoTable getTableTableInfo() {
		return( tableTableInfo );
	}

	public void setTableTableInfo( ICFSecTableInfoTable value ) {
		tableTableInfo = value;
	}

	public ICFSecTableInfoFactory getFactoryTableInfo() {
		return( factoryTableInfo );
	}

	public void setFactoryTableInfo( ICFSecTableInfoFactory value ) {
		factoryTableInfo = value;
	}

	public ICFSecTenantTable getTableTenant() {
		return( tableTenant );
	}

	public void setTableTenant( ICFSecTenantTable value ) {
		tableTenant = value;
	}

	public ICFSecTenantFactory getFactoryTenant() {
		return( factoryTenant );
	}

	public void setFactoryTenant( ICFSecTenantFactory value ) {
		factoryTenant = value;
	}

	public void bootstrapSchema(CFSecTableData tableData[]) {
		getSchemaService().bootstrapSchema(tableData);
	}

	public void bootstrapAllTablesSecurity(CFLibDbKeyHash256 clusterId, CFLibDbKeyHash256 tenantId, CFSecTableData tableData[]) {
		getSchemaService().bootstrapAllTablesSecurity(clusterId, tenantId, tableData);
	}
}
