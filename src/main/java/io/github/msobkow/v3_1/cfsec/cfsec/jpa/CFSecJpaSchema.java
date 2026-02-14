// Description: Java 25 JPA implementation of a CFSec schema.

/*
 *	io.github.msobkow.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	This file is part of Mark's Code Fractal CFSec.
 *	
 *	Mark's Code Fractal CFSec is available under dual commercial license from
 *	Mark Stephen Sobkow, or under the terms of the GNU Library General Public License,
 *	Version 3 or later.
 *	
 *	Mark's Code Fractal CFSec is free software: you can redistribute it and/or
 *	modify it under the terms of the GNU Library General Public License as published by
 *	the Free Software Foundation, either version 3 of the License, or
 *	(at your option) any later version.
 *	
 *	Mark's Code Fractal CFSec is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *	
 *	You should have received a copy of the GNU Library General Public License
 *	along with Mark's Code Fractal CFSec.  If not, see <https://www.gnu.org/licenses/>.
 *	
 *	If you wish to modify and use this code without publishing your changes in order to
 *	tie it to proprietary code, please contact Mark Stephen Sobkow
 *	for a commercial license at mark.sobkow@gmail.com
 *	
 */

package io.github.msobkow.v3_1.cfsec.cfsec.jpa;
//package io.github.msobkow.v3_1.cfsec.cfsec.jpa;

import java.io.Serializable;
import java.math.*;
import java.time.*;
import java.net.InetAddress;
import java.util.*;
import jakarta.persistence.*;
import jakarta.transaction.Transactional;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.text.StringEscapeUtils;
import io.github.msobkow.v3_1.cflib.*;
import io.github.msobkow.v3_1.cflib.dbutil.*;
import io.github.msobkow.v3_1.cflib.xml.CFLibXmlUtil;
import io.github.msobkow.v3_1.cfsec.cfsec.*;

public class CFSecJpaSchema
	implements ICFSecSchema
{
	protected static ICFSecTablePerms tablePerms;
	protected ICFSecClusterTable tableCluster;
	protected ICFSecHostNodeTable tableHostNode;
	protected ICFSecISOCcyTable tableISOCcy;
	protected ICFSecISOCtryTable tableISOCtry;
	protected ICFSecISOCtryCcyTable tableISOCtryCcy;
	protected ICFSecISOCtryLangTable tableISOCtryLang;
	protected ICFSecISOLangTable tableISOLang;
	protected ICFSecISOTZoneTable tableISOTZone;
	protected ICFSecSecDeviceTable tableSecDevice;
	protected ICFSecSecGroupTable tableSecGroup;
	protected ICFSecSecGrpIncTable tableSecGrpInc;
	protected ICFSecSecGrpMembTable tableSecGrpMemb;
	protected ICFSecSecSessionTable tableSecSession;
	protected ICFSecSecUserTable tableSecUser;
	protected ICFSecServiceTable tableService;
	protected ICFSecServiceTypeTable tableServiceType;
	protected ICFSecSysClusterTable tableSysCluster;
	protected ICFSecTSecGroupTable tableTSecGroup;
	protected ICFSecTSecGrpIncTable tableTSecGrpInc;
	protected ICFSecTSecGrpMembTable tableTSecGrpMemb;
	protected ICFSecTenantTable tableTenant;

	protected ICFSecClusterFactory factoryCluster;
	protected ICFSecHostNodeFactory factoryHostNode;
	protected ICFSecISOCcyFactory factoryISOCcy;
	protected ICFSecISOCtryFactory factoryISOCtry;
	protected ICFSecISOCtryCcyFactory factoryISOCtryCcy;
	protected ICFSecISOCtryLangFactory factoryISOCtryLang;
	protected ICFSecISOLangFactory factoryISOLang;
	protected ICFSecISOTZoneFactory factoryISOTZone;
	protected ICFSecSecDeviceFactory factorySecDevice;
	protected ICFSecSecGroupFactory factorySecGroup;
	protected ICFSecSecGrpIncFactory factorySecGrpInc;
	protected ICFSecSecGrpMembFactory factorySecGrpMemb;
	protected ICFSecSecSessionFactory factorySecSession;
	protected ICFSecSecUserFactory factorySecUser;
	protected ICFSecServiceFactory factoryService;
	protected ICFSecServiceTypeFactory factoryServiceType;
	protected ICFSecSysClusterFactory factorySysCluster;
	protected ICFSecTSecGroupFactory factoryTSecGroup;
	protected ICFSecTSecGrpIncFactory factoryTSecGrpInc;
	protected ICFSecTSecGrpMembFactory factoryTSecGrpMemb;
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
	
		entry = ICFSecSchema.getClassMapByBackingClassCode(ICFSecHostNode.CLASS_CODE);
		if (entry != null) {
			entry.setBackingRecConstructor( new BackingRecConstructor() {
				@Override
				public Object instantiate() {
					ICFSecHostNode ret = new CFSecJpaHostNode();
					return(ret);
				}
			});
		}
		else {
			throw new CFLibNullArgumentException(CFSecJpaSchema.class, "wireRecConstructors", 0, "ICFSecSchema.getClassMapByBackingClassCode(ICFSecHostNode.CLASS_CODE)[" + ICFSecHostNode.CLASS_CODE + "]");
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
	
		entry = ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecDevice.CLASS_CODE);
		if (entry != null) {
			entry.setBackingRecConstructor( new BackingRecConstructor() {
				@Override
				public Object instantiate() {
					ICFSecSecDevice ret = new CFSecJpaSecDevice();
					return(ret);
				}
			});
		}
		else {
			throw new CFLibNullArgumentException(CFSecJpaSchema.class, "wireRecConstructors", 0, "ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecDevice.CLASS_CODE)[" + ICFSecSecDevice.CLASS_CODE + "]");
		}
	
		entry = ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecGroup.CLASS_CODE);
		if (entry != null) {
			entry.setBackingRecConstructor( new BackingRecConstructor() {
				@Override
				public Object instantiate() {
					ICFSecSecGroup ret = new CFSecJpaSecGroup();
					return(ret);
				}
			});
		}
		else {
			throw new CFLibNullArgumentException(CFSecJpaSchema.class, "wireRecConstructors", 0, "ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecGroup.CLASS_CODE)[" + ICFSecSecGroup.CLASS_CODE + "]");
		}
	
		entry = ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecGrpInc.CLASS_CODE);
		if (entry != null) {
			entry.setBackingRecConstructor( new BackingRecConstructor() {
				@Override
				public Object instantiate() {
					ICFSecSecGrpInc ret = new CFSecJpaSecGrpInc();
					return(ret);
				}
			});
		}
		else {
			throw new CFLibNullArgumentException(CFSecJpaSchema.class, "wireRecConstructors", 0, "ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecGrpInc.CLASS_CODE)[" + ICFSecSecGrpInc.CLASS_CODE + "]");
		}
	
		entry = ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecGrpMemb.CLASS_CODE);
		if (entry != null) {
			entry.setBackingRecConstructor( new BackingRecConstructor() {
				@Override
				public Object instantiate() {
					ICFSecSecGrpMemb ret = new CFSecJpaSecGrpMemb();
					return(ret);
				}
			});
		}
		else {
			throw new CFLibNullArgumentException(CFSecJpaSchema.class, "wireRecConstructors", 0, "ICFSecSchema.getClassMapByBackingClassCode(ICFSecSecGrpMemb.CLASS_CODE)[" + ICFSecSecGrpMemb.CLASS_CODE + "]");
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
	
		entry = ICFSecSchema.getClassMapByBackingClassCode(ICFSecService.CLASS_CODE);
		if (entry != null) {
			entry.setBackingRecConstructor( new BackingRecConstructor() {
				@Override
				public Object instantiate() {
					ICFSecService ret = new CFSecJpaService();
					return(ret);
				}
			});
		}
		else {
			throw new CFLibNullArgumentException(CFSecJpaSchema.class, "wireRecConstructors", 0, "ICFSecSchema.getClassMapByBackingClassCode(ICFSecService.CLASS_CODE)[" + ICFSecService.CLASS_CODE + "]");
		}
	
		entry = ICFSecSchema.getClassMapByBackingClassCode(ICFSecServiceType.CLASS_CODE);
		if (entry != null) {
			entry.setBackingRecConstructor( new BackingRecConstructor() {
				@Override
				public Object instantiate() {
					ICFSecServiceType ret = new CFSecJpaServiceType();
					return(ret);
				}
			});
		}
		else {
			throw new CFLibNullArgumentException(CFSecJpaSchema.class, "wireRecConstructors", 0, "ICFSecSchema.getClassMapByBackingClassCode(ICFSecServiceType.CLASS_CODE)[" + ICFSecServiceType.CLASS_CODE + "]");
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
	
		entry = ICFSecSchema.getClassMapByBackingClassCode(ICFSecTSecGroup.CLASS_CODE);
		if (entry != null) {
			entry.setBackingRecConstructor( new BackingRecConstructor() {
				@Override
				public Object instantiate() {
					ICFSecTSecGroup ret = new CFSecJpaTSecGroup();
					return(ret);
				}
			});
		}
		else {
			throw new CFLibNullArgumentException(CFSecJpaSchema.class, "wireRecConstructors", 0, "ICFSecSchema.getClassMapByBackingClassCode(ICFSecTSecGroup.CLASS_CODE)[" + ICFSecTSecGroup.CLASS_CODE + "]");
		}
	
		entry = ICFSecSchema.getClassMapByBackingClassCode(ICFSecTSecGrpInc.CLASS_CODE);
		if (entry != null) {
			entry.setBackingRecConstructor( new BackingRecConstructor() {
				@Override
				public Object instantiate() {
					ICFSecTSecGrpInc ret = new CFSecJpaTSecGrpInc();
					return(ret);
				}
			});
		}
		else {
			throw new CFLibNullArgumentException(CFSecJpaSchema.class, "wireRecConstructors", 0, "ICFSecSchema.getClassMapByBackingClassCode(ICFSecTSecGrpInc.CLASS_CODE)[" + ICFSecTSecGrpInc.CLASS_CODE + "]");
		}
	
		entry = ICFSecSchema.getClassMapByBackingClassCode(ICFSecTSecGrpMemb.CLASS_CODE);
		if (entry != null) {
			entry.setBackingRecConstructor( new BackingRecConstructor() {
				@Override
				public Object instantiate() {
					ICFSecTSecGrpMemb ret = new CFSecJpaTSecGrpMemb();
					return(ret);
				}
			});
		}
		else {
			throw new CFLibNullArgumentException(CFSecJpaSchema.class, "wireRecConstructors", 0, "ICFSecSchema.getClassMapByBackingClassCode(ICFSecTSecGrpMemb.CLASS_CODE)[" + ICFSecTSecGrpMemb.CLASS_CODE + "]");
		}
	
	}

	@Override
	public void wireTableTableInstances() {
		if (tableCluster == null || !(tableCluster instanceof CFSecJpaClusterTable)) {
			tableCluster = new CFSecJpaClusterTable(this);
		}
		if (tableHostNode == null || !(tableHostNode instanceof CFSecJpaHostNodeTable)) {
			tableHostNode = new CFSecJpaHostNodeTable(this);
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
		if (tableSecDevice == null || !(tableSecDevice instanceof CFSecJpaSecDeviceTable)) {
			tableSecDevice = new CFSecJpaSecDeviceTable(this);
		}
		if (tableSecGroup == null || !(tableSecGroup instanceof CFSecJpaSecGroupTable)) {
			tableSecGroup = new CFSecJpaSecGroupTable(this);
		}
		if (tableSecGrpInc == null || !(tableSecGrpInc instanceof CFSecJpaSecGrpIncTable)) {
			tableSecGrpInc = new CFSecJpaSecGrpIncTable(this);
		}
		if (tableSecGrpMemb == null || !(tableSecGrpMemb instanceof CFSecJpaSecGrpMembTable)) {
			tableSecGrpMemb = new CFSecJpaSecGrpMembTable(this);
		}
		if (tableSecSession == null || !(tableSecSession instanceof CFSecJpaSecSessionTable)) {
			tableSecSession = new CFSecJpaSecSessionTable(this);
		}
		if (tableSecUser == null || !(tableSecUser instanceof CFSecJpaSecUserTable)) {
			tableSecUser = new CFSecJpaSecUserTable(this);
		}
		if (tableService == null || !(tableService instanceof CFSecJpaServiceTable)) {
			tableService = new CFSecJpaServiceTable(this);
		}
		if (tableServiceType == null || !(tableServiceType instanceof CFSecJpaServiceTypeTable)) {
			tableServiceType = new CFSecJpaServiceTypeTable(this);
		}
		if (tableSysCluster == null || !(tableSysCluster instanceof CFSecJpaSysClusterTable)) {
			tableSysCluster = new CFSecJpaSysClusterTable(this);
		}
		if (tableTenant == null || !(tableTenant instanceof CFSecJpaTenantTable)) {
			tableTenant = new CFSecJpaTenantTable(this);
		}
		if (tableTSecGroup == null || !(tableTSecGroup instanceof CFSecJpaTSecGroupTable)) {
			tableTSecGroup = new CFSecJpaTSecGroupTable(this);
		}
		if (tableTSecGrpInc == null || !(tableTSecGrpInc instanceof CFSecJpaTSecGrpIncTable)) {
			tableTSecGrpInc = new CFSecJpaTSecGrpIncTable(this);
		}
		if (tableTSecGrpMemb == null || !(tableTSecGrpMemb instanceof CFSecJpaTSecGrpMembTable)) {
			tableTSecGrpMemb = new CFSecJpaTSecGrpMembTable(this);
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

	public CFSecJpaSchema() {

		tableCluster = null;
		tableHostNode = null;
		tableISOCcy = null;
		tableISOCtry = null;
		tableISOCtryCcy = null;
		tableISOCtryLang = null;
		tableISOLang = null;
		tableISOTZone = null;
		tableSecDevice = null;
		tableSecGroup = null;
		tableSecGrpInc = null;
		tableSecGrpMemb = null;
		tableSecSession = null;
		tableSecUser = null;
		tableService = null;
		tableServiceType = null;
		tableSysCluster = null;
		tableTSecGroup = null;
		tableTSecGrpInc = null;
		tableTSecGrpMemb = null;
		tableTenant = null;

		factoryCluster = new CFSecJpaClusterDefaultFactory();
		factoryHostNode = new CFSecJpaHostNodeDefaultFactory();
		factoryISOCcy = new CFSecJpaISOCcyDefaultFactory();
		factoryISOCtry = new CFSecJpaISOCtryDefaultFactory();
		factoryISOCtryCcy = new CFSecJpaISOCtryCcyDefaultFactory();
		factoryISOCtryLang = new CFSecJpaISOCtryLangDefaultFactory();
		factoryISOLang = new CFSecJpaISOLangDefaultFactory();
		factoryISOTZone = new CFSecJpaISOTZoneDefaultFactory();
		factorySecDevice = new CFSecJpaSecDeviceDefaultFactory();
		factorySecGroup = new CFSecJpaSecGroupDefaultFactory();
		factorySecGrpInc = new CFSecJpaSecGrpIncDefaultFactory();
		factorySecGrpMemb = new CFSecJpaSecGrpMembDefaultFactory();
		factorySecSession = new CFSecJpaSecSessionDefaultFactory();
		factorySecUser = new CFSecJpaSecUserDefaultFactory();
		factoryService = new CFSecJpaServiceDefaultFactory();
		factoryServiceType = new CFSecJpaServiceTypeDefaultFactory();
		factorySysCluster = new CFSecJpaSysClusterDefaultFactory();
		factoryTSecGroup = new CFSecJpaTSecGroupDefaultFactory();
		factoryTSecGrpInc = new CFSecJpaTSecGrpIncDefaultFactory();
		factoryTSecGrpMemb = new CFSecJpaTSecGrpMembDefaultFactory();
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
	public CFLibDbKeyHash256 nextServiceTypeIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextTenantIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextHostNodeIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextSecGroupIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextSecGrpIncIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextSecGrpMembIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextServiceIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextTSecGroupIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextTSecGrpIncIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextTSecGrpMembIdGen() {
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

	public ICFSecHostNodeTable getTableHostNode() {
		return( tableHostNode );
	}

	public void setTableHostNode( ICFSecHostNodeTable value ) {
		tableHostNode = value;
	}

	public ICFSecHostNodeFactory getFactoryHostNode() {
		return( factoryHostNode );
	}

	public void setFactoryHostNode( ICFSecHostNodeFactory value ) {
		factoryHostNode = value;
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

	public ICFSecSecDeviceTable getTableSecDevice() {
		return( tableSecDevice );
	}

	public void setTableSecDevice( ICFSecSecDeviceTable value ) {
		tableSecDevice = value;
	}

	public ICFSecSecDeviceFactory getFactorySecDevice() {
		return( factorySecDevice );
	}

	public void setFactorySecDevice( ICFSecSecDeviceFactory value ) {
		factorySecDevice = value;
	}

	public ICFSecSecGroupTable getTableSecGroup() {
		return( tableSecGroup );
	}

	public void setTableSecGroup( ICFSecSecGroupTable value ) {
		tableSecGroup = value;
	}

	public ICFSecSecGroupFactory getFactorySecGroup() {
		return( factorySecGroup );
	}

	public void setFactorySecGroup( ICFSecSecGroupFactory value ) {
		factorySecGroup = value;
	}

	public ICFSecSecGrpIncTable getTableSecGrpInc() {
		return( tableSecGrpInc );
	}

	public void setTableSecGrpInc( ICFSecSecGrpIncTable value ) {
		tableSecGrpInc = value;
	}

	public ICFSecSecGrpIncFactory getFactorySecGrpInc() {
		return( factorySecGrpInc );
	}

	public void setFactorySecGrpInc( ICFSecSecGrpIncFactory value ) {
		factorySecGrpInc = value;
	}

	public ICFSecSecGrpMembTable getTableSecGrpMemb() {
		return( tableSecGrpMemb );
	}

	public void setTableSecGrpMemb( ICFSecSecGrpMembTable value ) {
		tableSecGrpMemb = value;
	}

	public ICFSecSecGrpMembFactory getFactorySecGrpMemb() {
		return( factorySecGrpMemb );
	}

	public void setFactorySecGrpMemb( ICFSecSecGrpMembFactory value ) {
		factorySecGrpMemb = value;
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

	public ICFSecServiceTable getTableService() {
		return( tableService );
	}

	public void setTableService( ICFSecServiceTable value ) {
		tableService = value;
	}

	public ICFSecServiceFactory getFactoryService() {
		return( factoryService );
	}

	public void setFactoryService( ICFSecServiceFactory value ) {
		factoryService = value;
	}

	public ICFSecServiceTypeTable getTableServiceType() {
		return( tableServiceType );
	}

	public void setTableServiceType( ICFSecServiceTypeTable value ) {
		tableServiceType = value;
	}

	public ICFSecServiceTypeFactory getFactoryServiceType() {
		return( factoryServiceType );
	}

	public void setFactoryServiceType( ICFSecServiceTypeFactory value ) {
		factoryServiceType = value;
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

	public ICFSecTSecGroupTable getTableTSecGroup() {
		return( tableTSecGroup );
	}

	public void setTableTSecGroup( ICFSecTSecGroupTable value ) {
		tableTSecGroup = value;
	}

	public ICFSecTSecGroupFactory getFactoryTSecGroup() {
		return( factoryTSecGroup );
	}

	public void setFactoryTSecGroup( ICFSecTSecGroupFactory value ) {
		factoryTSecGroup = value;
	}

	public ICFSecTSecGrpIncTable getTableTSecGrpInc() {
		return( tableTSecGrpInc );
	}

	public void setTableTSecGrpInc( ICFSecTSecGrpIncTable value ) {
		tableTSecGrpInc = value;
	}

	public ICFSecTSecGrpIncFactory getFactoryTSecGrpInc() {
		return( factoryTSecGrpInc );
	}

	public void setFactoryTSecGrpInc( ICFSecTSecGrpIncFactory value ) {
		factoryTSecGrpInc = value;
	}

	public ICFSecTSecGrpMembTable getTableTSecGrpMemb() {
		return( tableTSecGrpMemb );
	}

	public void setTableTSecGrpMemb( ICFSecTSecGrpMembTable value ) {
		tableTSecGrpMemb = value;
	}

	public ICFSecTSecGrpMembFactory getFactoryTSecGrpMemb() {
		return( factoryTSecGrpMemb );
	}

	public void setFactoryTSecGrpMemb( ICFSecTSecGrpMembFactory value ) {
		factoryTSecGrpMemb = value;
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

	/**
	 *	Get the Table Permissions interface for the schema.
	 *
	 *	@return	The Table Permissions interface for the schema.
	 *
	 *	@throws CFLibNotSupportedException thrown by client-side implementations.
	 */
	public static ICFSecTablePerms getTablePerms() {
		return(tablePerms);
	}

	/**
	 *	Get the Table Permissions interface cast to this schema's implementation.
	 *
	 *	@return The Table Permissions interface for this schema.
	 */
	public static ICFSecTablePerms getCFSecTablePerms() {
		return (ICFSecTablePerms)getTablePerms();
	}

	/**
	 *	Set the Table Permissions interface for the schema.  All fractal subclasses of
	 *	the ICFSecTablePerms implement at least that interface plus their own
	 *	accessors.
	 *
	 *	@param	value	The Table Permissions interface to be used by the schema.
	 *
	 *	@throws CFLibNotSupportedException thrown by client-side implementations.
	 */
	public static void setTablePerms( ICFSecTablePerms value ) {
		if(value == null) {
			throw new CFLibNullArgumentException(CFSecJpaSchema.class, "setTablePerms", 1, "value");
		}
		tablePerms = value;
	}

	public void bootstrapSchema() {
		CFSecJpaSysCluster sysCluster;
		CFLibDbKeyHash256 systemClusterID;
		CFSecJpaCluster systemCluster;
		CFSecJpaSecUser adminUser;
		CFLibDbKeyHash256 adminUID;
		CFSecJpaSecSession bootstrapSession;
		CFLibDbKeyHash256 bootstrapSessionID;
		CFSecJpaTenant systemTenant;
		CFLibDbKeyHash256 systemTenantID;
		ICFSecSysCluster[] sysClusters = getTableSysCluster().readAllDerived(null);
		if (sysClusters != null && sysClusters.length == 1) {
			sysCluster = (CFSecJpaSysCluster)(sysClusters[0]);
			systemClusterID = sysCluster.getRequiredClusterId();
			if(systemClusterID == null || systemClusterID.isNull()) {
				throw new CFLibNullArgumentException(getClass(), "bootstrapSchema", 0, "systemClusterID");
			}
			systemCluster = (CFSecJpaCluster)(getTableCluster().readDerived(null, systemClusterID));
			if (systemCluster == null) {
				throw new CFLibNullArgumentException(getClass(), "bootstrapSchema", 0, "systemCluster");
			}
			adminUID = systemCluster.getCreatedByUserId();
			if (adminUID == null || adminUID.isNull()) {
				throw new CFLibNullArgumentException(getClass(), "bootstrapSchema", 0, "adminUID");
			}
			adminUser = (CFSecJpaSecUser)(getTableSecUser().readDerived(null, adminUID));
			if( adminUser == null) {
				throw new CFLibNullArgumentException(getClass(), "bootstrapSchema", 0, "adminUser");
			}
			systemTenant = (CFSecJpaTenant)(getTableTenant().readDerivedByUNameIdx(null, systemClusterID, "system"));
			if( systemTenant == null) {
				systemTenantID = null;
				throw new CFLibNullArgumentException(getClass(), "bootstrapSchema", 0, "systemTenant");
			}
			else {
				systemTenantID = systemTenant.getPKey();
			}
			bootstrapSession = (CFSecJpaSecSession)(getTableSecSession().readDerivedByStartIdx(null, adminUID, systemCluster.getCreatedAt()));
			if (bootstrapSession == null) {
				ICFSecSecSession[] sessions = getTableSecSession().readDerivedBySecUserIdx(null, adminUID);
				if (sessions != null) {
					for (ICFSecSecSession cursess: sessions) {
						if (bootstrapSession == null || cursess.getRequiredStart().compareTo(bootstrapSession.getRequiredStart()) < 0) {
							bootstrapSession = (CFSecJpaSecSession)cursess;
						}
					}
				}
				if (bootstrapSession == null) {
					throw new CFLibNullArgumentException(getClass(), "bootstrapSchema", 0, "bootstrapSession");
				}
			}
			bootstrapSessionID = bootstrapSession.getPKey();
		}
		else {
			sysCluster = null;
			systemCluster = null;
			systemClusterID = null;
			adminUID = null;
			adminUser = null;
			bootstrapSession = null;
			bootstrapSessionID = null;
			systemTenant = null;
			systemTenantID = null;
		}
		LocalDateTime now = LocalDateTime.now();
		if (adminUID == null || adminUID.isNull()) {
			adminUID = new CFLibDbKeyHash256(0);
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
		if (ICFSecSchema.getSysClusterId() == null || ICFSecSchema.getSysClusterId().isNull()) {
			ICFSecSchema.setSysClusterId(systemClusterID);
		}
		else if ( ! ICFSecSchema.getSysClusterId().equals( systemClusterID )) {
			throw new CFLibInvalidArgumentException(getClass(), "bootstrapSchema", "Previously set system cluster id disagrees with new system cluster id", "Previously set system cluster id disagrees with new system cluster id");
		}
		if (ICFSecSchema.getSysTenantId() == null || ICFSecSchema.getSysTenantId().isNull()) {
			ICFSecSchema.setSysTenantId(systemTenantID);
		}
		else if ( ! ICFSecSchema.getSysTenantId().equals( systemTenantID )) {
			throw new CFLibInvalidArgumentException(getClass(), "bootstrapSchema", "Previously set system tenant id disagrees with new system tenant id", "Previously set system tenant id disagrees with new system tenant id");
		}
		if (ICFSecSchema.getSysAdminId() == null || ICFSecSchema.getSysAdminId().isNull()) {
			ICFSecSchema.setSysAdminId(adminUID);
		}
		else if ( ! ICFSecSchema.getSysAdminId().equals( adminUID )) {
			throw new CFLibInvalidArgumentException(getClass(), "bootstrapSchema", "Previously set system admin id disagrees with new system admin id", "Previously set system admin id disagrees with new system admin id");
		}

		String fqdn;
		try {
			InetAddress localHost = InetAddress.getLocalHost();
			fqdn = localHost.getCanonicalHostName();
		} catch (java.net.UnknownHostException e) {
			fqdn = "localhost";
		}
		if (systemCluster == null) {
			systemCluster = (CFSecJpaCluster)(getFactoryCluster().newRec());
			systemCluster.setPKey(systemClusterID);
			systemCluster.setCreatedByUserId(adminUID);
			systemCluster.setUpdatedByUserId(adminUID);
			systemCluster.setCreatedAt(now);
			systemCluster.setUpdatedAt(now);
			systemCluster.setRequiredFullDomName(fqdn);
			systemCluster.setRequiredDescription("System cluster for " + fqdn);
			systemCluster = (CFSecJpaCluster)(getTableCluster().createCluster(null, systemCluster));
			systemClusterID = systemCluster.getPKey();
		}
		if (adminUser == null) {
			adminUser = (CFSecJpaSecUser)(getFactorySecUser().newRec());
			adminUser.setCreatedByUserId(adminUID);
			adminUser.setUpdatedByUserId(adminUID);
			adminUser.setCreatedAt(now);
			adminUser.setUpdatedAt(now);
			adminUser.setPKey(adminUID);
			adminUser.setRequiredLoginId("sysadmin");
			adminUser.setRequiredEMailAddress("sysadmin@" + fqdn);
			adminUser.setRequiredPasswordHash(ICFSecSchema.getPasswordHash("ChangeOnInstall"));
			adminUser = (CFSecJpaSecUser)(getTableSecUser().createSecUser(null, adminUser));
			adminUID = adminUser.getPKey();
		}
		if (systemTenant == null) {
			systemTenant = (CFSecJpaTenant)(getFactoryTenant().newRec());
			systemTenant.setPKey(systemTenantID);
			systemTenant.setCreatedByUserId(adminUID);
			systemTenant.setUpdatedByUserId(adminUID);
			systemTenant.setCreatedAt(now);
			systemTenant.setUpdatedAt(now);
			systemTenant.setRequiredContainerCluster(systemClusterID);
			systemTenant.setRequiredTenantName("system");
			systemTenant = (CFSecJpaTenant)(getTableTenant().createTenant(null, systemTenant));
			systemTenantID = systemTenant.getPKey();
		}
		if (bootstrapSession == null) {
			bootstrapSession = (CFSecJpaSecSession)(getFactorySecSession().newRec());
			bootstrapSession.setPKey(bootstrapSessionID);
			bootstrapSession.setRequiredContainerSecUser(adminUID);
			bootstrapSession.setRequiredParentSecProxy(adminUID);
			bootstrapSession.setOptionalSecDevName(null);
			bootstrapSession.setRequiredStart(now);
			bootstrapSession.setOptionalFinish(null);
			bootstrapSession = (CFSecJpaSecSession)(getTableSecSession().createSecSession(null, bootstrapSession));
			bootstrapSessionID = bootstrapSession.getPKey();
		}
		if (sysCluster == null) {
			sysCluster = (CFSecJpaSysCluster)(getFactorySysCluster().newRec());
			sysCluster.setRequiredContainerCluster(systemClusterID);
			sysCluster = (CFSecJpaSysCluster)(getTableSysCluster().createSysCluster(null, sysCluster));
		}
		if (bootstrapSession.getOptionalFinish() == null) {
			bootstrapSession.setOptionalFinish(LocalDateTime.now());
			bootstrapSession = (CFSecJpaSecSession)(getTableSecSession().updateSecSession(null, bootstrapSession));
		}

	}
}
