// Description: Java 25 JPA implementation of a CFSec factory service.

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
import server.markhome.mcf.v3_1.cflib.xml.CFLibXmlUtil;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.text.StringEscapeUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import server.markhome.mcf.v3_1.cfsec.cfsec.*;

/**
 *	JPA Factory Services for schema CFSec as specified by ICFSecFactory.
 */
@Service("cfsec31JpaFactoryService")
public class CFSecJpaFactoryService
	implements ICFSecFactory
{

	@Autowired
	@Qualifier("cfsec31JpaClusterFactoryService")
	protected CFSecJpaClusterFactoryService clusterFactoryService;

	@Autowired
	@Qualifier("cfsec31JpaTenantFactoryService")
	protected CFSecJpaTenantFactoryService tenantFactoryService;

	@Autowired
	@Qualifier("cfsec31JpaTableInfoFactoryService")
	protected CFSecJpaTableInfoFactoryService tableinfoFactoryService;

	@Autowired
	@Qualifier("cfsec31JpaISOCcyFactoryService")
	protected CFSecJpaISOCcyFactoryService isoccyFactoryService;

	@Autowired
	@Qualifier("cfsec31JpaISOCtryFactoryService")
	protected CFSecJpaISOCtryFactoryService isoctryFactoryService;

	@Autowired
	@Qualifier("cfsec31JpaISOCtryCcyFactoryService")
	protected CFSecJpaISOCtryCcyFactoryService isoctryccyFactoryService;

	@Autowired
	@Qualifier("cfsec31JpaISOCtryLangFactoryService")
	protected CFSecJpaISOCtryLangFactoryService isoctrylangFactoryService;

	@Autowired
	@Qualifier("cfsec31JpaISOLangFactoryService")
	protected CFSecJpaISOLangFactoryService isolangFactoryService;

	@Autowired
	@Qualifier("cfsec31JpaISOTZoneFactoryService")
	protected CFSecJpaISOTZoneFactoryService isotzoneFactoryService;

	@Autowired
	@Qualifier("cfsec31JpaSecUserFactoryService")
	protected CFSecJpaSecUserFactoryService secuserFactoryService;

	@Autowired
	@Qualifier("cfsec31JpaSecUserPasswordFactoryService")
	protected CFSecJpaSecUserPasswordFactoryService secuserpasswordFactoryService;

	@Autowired
	@Qualifier("cfsec31JpaSecUserEMConfFactoryService")
	protected CFSecJpaSecUserEMConfFactoryService secuseremconfFactoryService;

	@Autowired
	@Qualifier("cfsec31JpaSecUserPWResetFactoryService")
	protected CFSecJpaSecUserPWResetFactoryService secuserpwresetFactoryService;

	@Autowired
	@Qualifier("cfsec31JpaSecUserPWHistoryFactoryService")
	protected CFSecJpaSecUserPWHistoryFactoryService secuserpwhistoryFactoryService;

	@Autowired
	@Qualifier("cfsec31JpaSecSysGrpFactoryService")
	protected CFSecJpaSecSysGrpFactoryService secsysgrpFactoryService;

	@Autowired
	@Qualifier("cfsec31JpaSecSysGrpIncFactoryService")
	protected CFSecJpaSecSysGrpIncFactoryService secsysgrpincFactoryService;

	@Autowired
	@Qualifier("cfsec31JpaSecSysGrpMembFactoryService")
	protected CFSecJpaSecSysGrpMembFactoryService secsysgrpmembFactoryService;

	@Autowired
	@Qualifier("cfsec31JpaSecClusGrpFactoryService")
	protected CFSecJpaSecClusGrpFactoryService secclusgrpFactoryService;

	@Autowired
	@Qualifier("cfsec31JpaSecClusGrpMembFactoryService")
	protected CFSecJpaSecClusGrpMembFactoryService secclusgrpmembFactoryService;

	@Autowired
	@Qualifier("cfsec31JpaSecTentGrpFactoryService")
	protected CFSecJpaSecTentGrpFactoryService sectentgrpFactoryService;

	@Autowired
	@Qualifier("cfsec31JpaSecTentGrpMembFactoryService")
	protected CFSecJpaSecTentGrpMembFactoryService sectentgrpmembFactoryService;

	@Autowired
	@Qualifier("cfsec31JpaSecSysRoleFactoryService")
	protected CFSecJpaSecSysRoleFactoryService secsysroleFactoryService;

	@Autowired
	@Qualifier("cfsec31JpaSecSysRoleEnablesFactoryService")
	protected CFSecJpaSecSysRoleEnablesFactoryService secsysroleenablesFactoryService;

	@Autowired
	@Qualifier("cfsec31JpaSecSysRoleMembFactoryService")
	protected CFSecJpaSecSysRoleMembFactoryService secsysrolemembFactoryService;

	@Autowired
	@Qualifier("cfsec31JpaSecClusRoleFactoryService")
	protected CFSecJpaSecClusRoleFactoryService secclusroleFactoryService;

	@Autowired
	@Qualifier("cfsec31JpaSecClusRoleMembFactoryService")
	protected CFSecJpaSecClusRoleMembFactoryService secclusrolemembFactoryService;

	@Autowired
	@Qualifier("cfsec31JpaSecTentRoleFactoryService")
	protected CFSecJpaSecTentRoleFactoryService sectentroleFactoryService;

	@Autowired
	@Qualifier("cfsec31JpaSecTentRoleMembFactoryService")
	protected CFSecJpaSecTentRoleMembFactoryService sectentrolemembFactoryService;

	@Autowired
	@Qualifier("cfsec31JpaSecSessionFactoryService")
	protected CFSecJpaSecSessionFactoryService secsessionFactoryService;

	@Autowired
	@Qualifier("cfsec31JpaSysClusterFactoryService")
	protected CFSecJpaSysClusterFactoryService sysclusterFactoryService;


	public CFSecJpaFactoryService() { }

	@Override
	public ICFSecClusterFactory getFactoryCluster() {
		return(clusterFactoryService);
	}

	public CFSecJpaClusterFactoryService getClusterFactoryService() {
		return(clusterFactoryService);
	}

	@Override
	public ICFSecTenantFactory getFactoryTenant() {
		return(tenantFactoryService);
	}

	public CFSecJpaTenantFactoryService getTenantFactoryService() {
		return(tenantFactoryService);
	}

	@Override
	public ICFSecTableInfoFactory getFactoryTableInfo() {
		return(tableinfoFactoryService);
	}

	public CFSecJpaTableInfoFactoryService getTableInfoFactoryService() {
		return(tableinfoFactoryService);
	}

	@Override
	public ICFSecISOCcyFactory getFactoryISOCcy() {
		return(isoccyFactoryService);
	}

	public CFSecJpaISOCcyFactoryService getISOCcyFactoryService() {
		return(isoccyFactoryService);
	}

	@Override
	public ICFSecISOCtryFactory getFactoryISOCtry() {
		return(isoctryFactoryService);
	}

	public CFSecJpaISOCtryFactoryService getISOCtryFactoryService() {
		return(isoctryFactoryService);
	}

	@Override
	public ICFSecISOCtryCcyFactory getFactoryISOCtryCcy() {
		return(isoctryccyFactoryService);
	}

	public CFSecJpaISOCtryCcyFactoryService getISOCtryCcyFactoryService() {
		return(isoctryccyFactoryService);
	}

	@Override
	public ICFSecISOCtryLangFactory getFactoryISOCtryLang() {
		return(isoctrylangFactoryService);
	}

	public CFSecJpaISOCtryLangFactoryService getISOCtryLangFactoryService() {
		return(isoctrylangFactoryService);
	}

	@Override
	public ICFSecISOLangFactory getFactoryISOLang() {
		return(isolangFactoryService);
	}

	public CFSecJpaISOLangFactoryService getISOLangFactoryService() {
		return(isolangFactoryService);
	}

	@Override
	public ICFSecISOTZoneFactory getFactoryISOTZone() {
		return(isotzoneFactoryService);
	}

	public CFSecJpaISOTZoneFactoryService getISOTZoneFactoryService() {
		return(isotzoneFactoryService);
	}

	@Override
	public ICFSecSecUserFactory getFactorySecUser() {
		return(secuserFactoryService);
	}

	public CFSecJpaSecUserFactoryService getSecUserFactoryService() {
		return(secuserFactoryService);
	}

	@Override
	public ICFSecSecUserPasswordFactory getFactorySecUserPassword() {
		return(secuserpasswordFactoryService);
	}

	public CFSecJpaSecUserPasswordFactoryService getSecUserPasswordFactoryService() {
		return(secuserpasswordFactoryService);
	}

	@Override
	public ICFSecSecUserEMConfFactory getFactorySecUserEMConf() {
		return(secuseremconfFactoryService);
	}

	public CFSecJpaSecUserEMConfFactoryService getSecUserEMConfFactoryService() {
		return(secuseremconfFactoryService);
	}

	@Override
	public ICFSecSecUserPWResetFactory getFactorySecUserPWReset() {
		return(secuserpwresetFactoryService);
	}

	public CFSecJpaSecUserPWResetFactoryService getSecUserPWResetFactoryService() {
		return(secuserpwresetFactoryService);
	}

	@Override
	public ICFSecSecUserPWHistoryFactory getFactorySecUserPWHistory() {
		return(secuserpwhistoryFactoryService);
	}

	public CFSecJpaSecUserPWHistoryFactoryService getSecUserPWHistoryFactoryService() {
		return(secuserpwhistoryFactoryService);
	}

	@Override
	public ICFSecSecSysGrpFactory getFactorySecSysGrp() {
		return(secsysgrpFactoryService);
	}

	public CFSecJpaSecSysGrpFactoryService getSecSysGrpFactoryService() {
		return(secsysgrpFactoryService);
	}

	@Override
	public ICFSecSecSysGrpIncFactory getFactorySecSysGrpInc() {
		return(secsysgrpincFactoryService);
	}

	public CFSecJpaSecSysGrpIncFactoryService getSecSysGrpIncFactoryService() {
		return(secsysgrpincFactoryService);
	}

	@Override
	public ICFSecSecSysGrpMembFactory getFactorySecSysGrpMemb() {
		return(secsysgrpmembFactoryService);
	}

	public CFSecJpaSecSysGrpMembFactoryService getSecSysGrpMembFactoryService() {
		return(secsysgrpmembFactoryService);
	}

	@Override
	public ICFSecSecClusGrpFactory getFactorySecClusGrp() {
		return(secclusgrpFactoryService);
	}

	public CFSecJpaSecClusGrpFactoryService getSecClusGrpFactoryService() {
		return(secclusgrpFactoryService);
	}

	@Override
	public ICFSecSecClusGrpMembFactory getFactorySecClusGrpMemb() {
		return(secclusgrpmembFactoryService);
	}

	public CFSecJpaSecClusGrpMembFactoryService getSecClusGrpMembFactoryService() {
		return(secclusgrpmembFactoryService);
	}

	@Override
	public ICFSecSecTentGrpFactory getFactorySecTentGrp() {
		return(sectentgrpFactoryService);
	}

	public CFSecJpaSecTentGrpFactoryService getSecTentGrpFactoryService() {
		return(sectentgrpFactoryService);
	}

	@Override
	public ICFSecSecTentGrpMembFactory getFactorySecTentGrpMemb() {
		return(sectentgrpmembFactoryService);
	}

	public CFSecJpaSecTentGrpMembFactoryService getSecTentGrpMembFactoryService() {
		return(sectentgrpmembFactoryService);
	}

	@Override
	public ICFSecSecSysRoleFactory getFactorySecSysRole() {
		return(secsysroleFactoryService);
	}

	public CFSecJpaSecSysRoleFactoryService getSecSysRoleFactoryService() {
		return(secsysroleFactoryService);
	}

	@Override
	public ICFSecSecSysRoleEnablesFactory getFactorySecSysRoleEnables() {
		return(secsysroleenablesFactoryService);
	}

	public CFSecJpaSecSysRoleEnablesFactoryService getSecSysRoleEnablesFactoryService() {
		return(secsysroleenablesFactoryService);
	}

	@Override
	public ICFSecSecSysRoleMembFactory getFactorySecSysRoleMemb() {
		return(secsysrolemembFactoryService);
	}

	public CFSecJpaSecSysRoleMembFactoryService getSecSysRoleMembFactoryService() {
		return(secsysrolemembFactoryService);
	}

	@Override
	public ICFSecSecClusRoleFactory getFactorySecClusRole() {
		return(secclusroleFactoryService);
	}

	public CFSecJpaSecClusRoleFactoryService getSecClusRoleFactoryService() {
		return(secclusroleFactoryService);
	}

	@Override
	public ICFSecSecClusRoleMembFactory getFactorySecClusRoleMemb() {
		return(secclusrolemembFactoryService);
	}

	public CFSecJpaSecClusRoleMembFactoryService getSecClusRoleMembFactoryService() {
		return(secclusrolemembFactoryService);
	}

	@Override
	public ICFSecSecTentRoleFactory getFactorySecTentRole() {
		return(sectentroleFactoryService);
	}

	public CFSecJpaSecTentRoleFactoryService getSecTentRoleFactoryService() {
		return(sectentroleFactoryService);
	}

	@Override
	public ICFSecSecTentRoleMembFactory getFactorySecTentRoleMemb() {
		return(sectentrolemembFactoryService);
	}

	public CFSecJpaSecTentRoleMembFactoryService getSecTentRoleMembFactoryService() {
		return(sectentrolemembFactoryService);
	}

	@Override
	public ICFSecSecSessionFactory getFactorySecSession() {
		return(secsessionFactoryService);
	}

	public CFSecJpaSecSessionFactoryService getSecSessionFactoryService() {
		return(secsessionFactoryService);
	}

	@Override
	public ICFSecSysClusterFactory getFactorySysCluster() {
		return(sysclusterFactoryService);
	}

	public CFSecJpaSysClusterFactoryService getSysClusterFactoryService() {
		return(sysclusterFactoryService);
	}

}
